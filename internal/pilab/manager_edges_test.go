package pilab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPartialExitRequiresCompleteReportProtocol(t *testing.T) {
	for _, valid := range []bool{false, true} {
		runtime := &fakeRuntime{run: func(_ context.Context, _ string, _ Input, emit func(Event) error) error {
			if valid {
				if err := emit(fixtureEvent("report", "coordinator", map[string]string{"text": "Reached budget; incomplete fixture results."})); err != nil {
					return err
				}
				if err := emit(fixtureEvent("complete", "coordinator", map[string]string{"status": "partial"})); err != nil {
					return err
				}
			}
			return ErrPartialExit
		}}
		m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
		run, err := m.Create("alice", fixtureRequest(), fixtureModel())
		if err != nil {
			t.Fatal(err)
		}
		result := waitRun(t, m, run.ID)
		m.Close()
		expected := "failed"
		if valid {
			expected = "partial"
		}
		if result.Status != expected {
			t.Fatalf("valid=%v status=%s", valid, result.Status)
		}
	}
}

func TestCompletedReportWithoutCoordinatorEndIsNotSuccess(t *testing.T) {
	runtime := &fakeRuntime{run: func(_ context.Context, _ string, _ Input, emit func(Event) error) error {
		if err := emit(fixtureEvent("report", "coordinator", map[string]string{"text": "unsupported success claim"})); err != nil {
			return err
		}
		return emit(fixtureEvent("complete", "coordinator", map[string]string{"status": "completed"}))
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
	defer m.Close()
	run, err := m.Create("alice", fixtureRequest(), fixtureModel())
	if err != nil {
		t.Fatal(err)
	}
	if got := waitRun(t, m, run.ID); got.Status != "failed" {
		t.Fatal(got)
	}
}

func TestProjectionUnicodeAndBudgetLimits(t *testing.T) {
	run := Run{Limits: DefaultLimits}
	if err := projectEvent(&run, fixtureEvent("agent_start", "coordinator", Agent{Role: "coordinator"})); err != nil {
		t.Fatal(err)
	}
	if err := projectEvent(&run, fixtureEvent("agent_end", "coordinator", Agent{Status: "completed", Summary: strings.Repeat("中", 24000)})); err != nil {
		t.Fatal("Unicode text within character budget rejected", err)
	}
	for i := 0; i < 256; i++ {
		run.Nodes = append(run.Nodes, Node{ID: strings.Repeat("n", i+1)})
	}
	if err := projectEvent(&run, fixtureEvent("node", "coordinator", Node{ID: "overflow", Label: "overflow"})); err == nil {
		t.Fatal("node budget bypass")
	}
	if err := projectEvent(&run, fixtureEvent("finding", "coordinator", Finding{ID: "f", Status: "confirmed", Severity: "high"})); err == nil {
		t.Fatal("unverified confirmed finding accepted")
	}
}

func TestEventBudgetAndStorageErrorsStopRun(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	runtime := &fakeRuntime{run: func(ctx context.Context, _ string, _ Input, emit func(Event) error) error {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return emit(fixtureEvent("message", "coordinator", map[string]string{"text": "too late"}))
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
	defer m.Close()
	run, err := m.Create("alice", fixtureRequest(), fixtureModel())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	m.mu.Lock()
	m.runs[run.ID].EventCount = maxEvents
	m.mu.Unlock()
	close(release)
	if got := waitRun(t, m, run.ID); got.Status != "failed" {
		t.Fatal(got)
	}
	root := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(root, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	broken := New(Options{Enabled: true, Root: root, Runtime: runtime})
	defer broken.Close()
	if _, err := broken.Create("alice", fixtureRequest(), fixtureModel()); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
}

func TestProtocolRedactionDoesNotCorruptGeneratedIdentity(t *testing.T) {
	for _, key := range []string{"completed", "coordinator"} {
		event := fixtureEvent("agent_end", "coordinator", map[string]string{"id": "coordinator", "status": "completed", "summary": key})
		clean, err := redactEvent(event, key)
		if err != nil {
			t.Fatal(err)
		}
		var data map[string]string
		if err := json.Unmarshal(clean.Data, &data); err != nil {
			t.Fatal(err)
		}
		if clean.AgentID != "coordinator" || data["id"] != "coordinator" || data["status"] != "completed" || data["summary"] != "[REDACTED]" {
			t.Fatal(clean, data)
		}
	}
}

func TestDefaultModelConfigurationProducesValidSDKInput(t *testing.T) {
	for _, provider := range []string{"openai", "claude"} {
		model := NormalizeModel(Model{Provider: provider, ID: "fixture", APIKey: "fixture-key", MaxTokens: 65536})
		if err := ValidateModel(model); err != nil {
			t.Fatal(err)
		}
		if model.BaseURL == "" || model.MaxTokens != 32768 || model.ContextWindow != 128000 {
			t.Fatal(model)
		}
	}
}
