package pilab

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRuntime struct {
	checkCalls atomic.Int32
	run        func(context.Context, string, Input, func(Event) error) error
}

func (r *fakeRuntime) Check(context.Context) error { r.checkCalls.Add(1); return nil }
func (r *fakeRuntime) Run(ctx context.Context, dir string, input Input, emit func(Event) error) error {
	return r.run(ctx, dir, input, emit)
}
func fixtureRequest() CreateRequest {
	return CreateRequest{Title: "独立试验", Prompt: "分析范围内的响应与待验证项", Scope: []string{"https://example.test"}, Authorized: true}
}
func fixtureModel() Model {
	return Model{Provider: "openai", ID: "fixture-model", APIKey: "secret-key-123", ContextWindow: 32000, MaxTokens: 1024}
}
func fixtureEvent(kind, agent string, data any) Event {
	raw, _ := json.Marshal(data)
	return Event{Type: kind, AgentID: agent, Data: raw}
}
func waitRun(t *testing.T, m *Manager, id string) Run {
	t.Helper()
	deadline := time.After(15 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		run, err := m.Get("alice", id)
		if err != nil {
			t.Fatal(err)
		}
		if !active(run.Status) {
			return run
		}
		select {
		case <-deadline:
			t.Fatal("run did not finish")
		case <-ticker.C:
		}
	}
}

func TestDisabledIsInert(t *testing.T) {
	root := filepath.Join(t.TempDir(), "must-not-exist")
	runtime := &fakeRuntime{}
	m := New(Options{Root: root, Runtime: runtime})
	defer m.Close()
	if s := m.Status(context.Background()); s.Enabled || s.Ready {
		t.Fatal(s)
	}
	if _, err := m.Create("alice", fixtureRequest(), fixtureModel()); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if runs, err := m.List("alice"); err != nil || len(runs) != 0 {
		t.Fatal(runs, err)
	}
	if runtime.checkCalls.Load() != 0 {
		t.Fatal("disabled module ran readiness check")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("disabled module created files")
	}
}

func TestRunPersistenceOwnershipProjectionAndRedaction(t *testing.T) {
	root := t.TempDir()
	runtime := &fakeRuntime{run: func(ctx context.Context, dir string, input Input, emit func(Event) error) error {
		if !strings.HasSuffix(dir, "workspace") || input.Model.APIKey != "secret-key-123" {
			return errors.New("invalid process input")
		}
		for _, ev := range []Event{
			fixtureEvent("agent_start", "coordinator", Agent{Role: "coordinator", Task: "inspect"}),
			fixtureEvent("node", "coordinator", Node{ID: "surface-1", Kind: "surface", Label: "入口"}),
			fixtureEvent("finding", "coordinator", Finding{ID: "finding-1", Title: "待验证", Severity: "low", Status: "hypothesis", Evidence: "secret-key-123"}),
			fixtureEvent("report", "coordinator", map[string]string{"text": "summary secret-key-123"}),
			fixtureEvent("agent_end", "coordinator", map[string]string{"status": "completed", "summary": "finished"}),
			fixtureEvent("complete", "", map[string]string{"status": "completed"}),
		} {
			if err := emit(ev); err != nil {
				return err
			}
		}
		return nil
	}}
	m := New(Options{Enabled: true, Root: root, Runtime: runtime})
	defer m.Close()
	run, err := m.Create("alice", fixtureRequest(), fixtureModel())
	if err != nil {
		t.Fatal(err)
	}
	result := waitRun(t, m, run.ID)
	if result.Status != "completed" || result.Report != "summary [REDACTED]" || result.Findings[0].Evidence != "[REDACTED]" || len(result.Nodes) != 1 || result.Agents[0].Status != "completed" {
		t.Fatalf("bad projection: %+v", result)
	}
	if _, err := m.Get("bob", run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-owner read", err)
	}
	if _, err := m.Cancel("bob", run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-owner cancel", err)
	}
	if _, err := m.Events("bob", run.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-owner events", err)
	}
	if items, err := m.List("bob"); err != nil || len(items) != 0 {
		t.Fatal(items, err)
	}
	page, err := m.Events("alice", run.ID, 0)
	if err != nil || page.Cursor != 6 || page.HasMore || len(page.Events) != 6 {
		t.Fatal(page, err)
	}
	if page, err := m.Events("alice", run.ID, 6); err != nil || len(page.Events) != 0 {
		t.Fatal(page, err)
	}
	// Returned state must not share mutable slices with the manager.
	result.Findings[0].Title = "tampered"
	copy, _ := m.Get("alice", run.ID)
	if copy.Findings[0].Title == "tampered" {
		t.Fatal("aliased state")
	}
	for _, name := range []string{"run.json", "events.ndjson"} {
		data, err := os.ReadFile(m.runPath(run.ID, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "secret-key-123") || strings.Contains(string(data), "api_key") {
			t.Fatal("credential persisted", name)
		}
	}
	reloaded := New(Options{Root: root})
	defer reloaded.Close()
	stored, err := reloaded.Get("alice", run.ID)
	if err != nil || stored.Status != "completed" || stored.Report != copy.Report {
		t.Fatal(stored, err)
	}
}

func TestCancellationGlobalConcurrencyAndRestart(t *testing.T) {
	runtime := &fakeRuntime{run: func(ctx context.Context, _ string, _ Input, emit func(Event) error) error {
		if err := emit(fixtureEvent("agent_start", "coordinator", Agent{Role: "coordinator"})); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
	run, err := m.Create("alice", fixtureRequest(), fixtureModel())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("bob", fixtureRequest(), fixtureModel()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	cancelled, err := m.Cancel("alice", run.ID)
	if err != nil || cancelled.Status != "cancelled" {
		t.Fatal(cancelled, err)
	}
	m.Close()
	if got, _ := m.Get("alice", run.ID); got.Status != "cancelled" {
		t.Fatal(got)
	}
	// Simulate a crash with an on-disk running record, never re-execute it.
	m.mu.Lock()
	m.runs[run.ID].Status = "running"
	err = m.saveLocked(m.runs[run.ID])
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	reloaded := New(Options{Root: m.options.Root})
	defer reloaded.Close()
	got, err := reloaded.Get("alice", run.ID)
	if err != nil || got.Status != "interrupted" {
		t.Fatal(got, err)
	}
}

func TestNoFalseSuccess(t *testing.T) {
	for _, scenario := range []string{"empty", "complete-without-report", "report-without-complete", "confirmed-finding", "provider-error"} {
		t.Run(scenario, func(t *testing.T) {
			runtime := &fakeRuntime{run: func(_ context.Context, _ string, _ Input, emit func(Event) error) error {
				switch scenario {
				case "complete-without-report":
					return emit(fixtureEvent("complete", "", map[string]string{"status": "completed"}))
				case "report-without-complete":
					return emit(fixtureEvent("report", "", map[string]string{"text": "incomplete"}))
				case "confirmed-finding":
					return emit(fixtureEvent("finding", "", Finding{ID: "invalid", Status: "confirmed", Severity: "high"}))
				case "provider-error":
					return errors.New("provider exposed secret-key-123")
				default:
					return nil
				}
			}}
			m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
			defer m.Close()
			run, err := m.Create("alice", fixtureRequest(), fixtureModel())
			if err != nil {
				t.Fatal(err)
			}
			result := waitRun(t, m, run.ID)
			if result.Status != "failed" || strings.Contains(result.Error, "secret-key") {
				t.Fatal(result)
			}
		})
	}
}

func TestEventPagination(t *testing.T) {
	runtime := &fakeRuntime{run: func(_ context.Context, _ string, _ Input, emit func(Event) error) error {
		for i := 0; i < 105; i++ {
			if err := emit(fixtureEvent("message", "coordinator", map[string]string{"text": "fixture"})); err != nil {
				return err
			}
		}
		if err := emit(fixtureEvent("report", "coordinator", map[string]string{"text": "done"})); err != nil {
			return err
		}
		return emit(fixtureEvent("complete", "", map[string]string{"status": "completed"}))
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
	defer m.Close()
	run, err := m.Create("alice", fixtureRequest(), fixtureModel())
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, m, run.ID)
	page, err := m.Events("alice", run.ID, 0)
	if err != nil || len(page.Events) != 100 || !page.HasMore {
		t.Fatal(page, err)
	}
	tail, err := m.Events("alice", run.ID, page.Cursor)
	if err != nil || len(tail.Events) != 7 || tail.HasMore {
		t.Fatal(tail, err)
	}
	if _, err := m.Events("alice", run.ID, 108); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}
