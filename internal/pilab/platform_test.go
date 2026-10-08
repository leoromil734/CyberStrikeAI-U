package pilab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func platformRequest() CreateRequest {
	r := fixtureRequest()
	r.Mode = ModePlatform
	r.ProjectID = "owned-project"
	r.Scope = []string{"10.20.0.0/24", "https://app.example.test/api", "排除第三方支付"}
	return r
}
func preparedFixture(req CreateRequest) *PreparedRun {
	return &PreparedRun{Platform: &PlatformInput{RoleName: "渗透测试", ProjectID: req.ProjectID, ConversationID: "bound-conversation", Instructions: "SERVER-ROLE-PRIVATE", Skills: []SkillInfo{{Name: "pentest-agent-os"}}, Tools: []ToolDefinition{{Name: "load_skill", InputSchema: map[string]interface{}{"type": "object"}}}}, Execute: func(context.Context, ToolCall) (*ToolReply, error) {
		return &ToolReply{ExecutionID: "actual-execution", Content: []ToolContent{{Type: "text", Text: "fixture skill"}}}, nil
	}}
}

func TestConfiguredPIRunConcurrencyRemainsBounded(t *testing.T) {
	runtime := &fakeRuntime{run: func(ctx context.Context, _ string, _ Input, _ func(Event) error) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime, MaxConcurrent: 2})
	defer m.Close()
	if _, err := m.Create("alice", fixtureRequest(), fixtureModel()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("bob", fixtureRequest(), fixtureModel()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create("charlie", fixtureRequest(), fixtureModel()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	status := m.Status(context.Background())
	if status.ActiveRuns != 2 || status.MaxConcurrentRuns != 2 {
		t.Fatal(status)
	}
}

func TestPlatformModeValidationAndFailClosedBinding(t *testing.T) {
	req, limits, err := ValidateRequest(platformRequest())
	if err != nil {
		t.Fatal(err)
	}
	if req.Role != "渗透测试" || limits.MaxTurns != 120 || limits.TimeoutSeconds != 3600 || len(req.Scope) != 3 {
		t.Fatal(req, limits)
	}
	for _, mutate := range []func(*CreateRequest){func(r *CreateRequest) { r.ProjectID = "" }, func(r *CreateRequest) { r.Role = "unexpected-role" }, func(r *CreateRequest) { r.MaxTurns = 501 }, func(r *CreateRequest) { r.MaxToolCalls = 2001 }, func(r *CreateRequest) { r.Mode = "unknown" }} {
		r := platformRequest()
		mutate(&r)
		if _, _, err := ValidateRequest(r); err == nil {
			t.Fatal("invalid platform request accepted", r)
		}
	}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: &fakeRuntime{}})
	defer m.Close()
	if _, err := m.Create("alice", platformRequest(), fixtureModel()); !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatal(err)
	}
}

func TestPlatformHooksMetadataAndFinalizationGate(t *testing.T) {
	type identityKey struct{}
	var starts, finishes, closes atomic.Int32
	runtime := &fakeRuntime{run: func(ctx context.Context, _ string, in Input, emit func(Event) error) error {
		if ctx.Value(identityKey{}) != "owner" || in.Mode != ModePlatform || in.Platform.RoleName != "渗透测试" {
			t.Error("platform identity lost")
		}
		if _, err := in.Execute(ctx, ToolCall{Name: "load_skill", AgentID: "coordinator", Arguments: map[string]interface{}{"name": "pentest-agent-os"}}); err != nil {
			return err
		}
		for _, event := range []Event{fixtureEvent("agent_start", "coordinator", Agent{Role: "coordinator"}), fixtureEvent("report", "coordinator", map[string]string{"text": "fixture report"}), fixtureEvent("agent_end", "coordinator", Agent{Status: "completed", Summary: "model stopped"}), fixtureEvent("complete", "coordinator", map[string]string{"status": "completed"})} {
			if err := emit(event); err != nil {
				return err
			}
		}
		return nil
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
	defer m.Close()
	prepare := func(_ context.Context, _ string, req CreateRequest) (*PreparedRun, error) {
		p := preparedFixture(req)
		p.Context = context.WithValue(context.Background(), identityKey{}, "owner")
		p.Start = func(context.Context, context.CancelFunc) error { starts.Add(1); return nil }
		p.Finish = func(r *Run) error {
			finishes.Add(1)
			if r.ConversationID != "bound-conversation" || len(r.ExecutionIDs) != 1 || len(r.Skills) != 1 {
				t.Error("execution references not attached", r)
			}
			r.Status = "partial"
			r.Error = "coverage gate: unresolved gap"
			r.Report += "\n阶段报告"
			return nil
		}
		p.Close = func() { closes.Add(1) }
		return p, nil
	}
	run, err := m.CreatePrepared("alice", platformRequest(), fixtureModel(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	result := waitRun(t, m, run.ID)
	m.Close()
	if result.Status != "partial" || !strings.Contains(result.Report, "阶段报告") || starts.Load() != 1 || finishes.Load() != 1 || closes.Load() != 1 {
		t.Fatal(result, starts.Load(), finishes.Load(), closes.Load())
	}
	data, err := os.ReadFile(m.runPath(run.ID, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SERVER-ROLE-PRIVATE") || strings.Contains(string(data), fixtureModel().APIKey) || strings.Contains(string(data), "bridge") {
		t.Fatal("private binding persisted")
	}
}

func TestPlatformCancellationInvokesFinishAndCleanup(t *testing.T) {
	var finishes, closes atomic.Int32
	started := make(chan struct{})
	runtime := &fakeRuntime{run: func(ctx context.Context, _ string, _ Input, _ func(Event) error) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}}
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: runtime})
	defer m.Close()
	run, err := m.CreatePrepared("alice", platformRequest(), fixtureModel(), func(_ context.Context, _ string, r CreateRequest) (*PreparedRun, error) {
		p := preparedFixture(r)
		p.Finish = func(r *Run) error {
			finishes.Add(1)
			if r.Status != "cancelled" {
				t.Error(r.Status)
			}
			return nil
		}
		p.Close = func() { closes.Add(1) }
		return p, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := m.Cancel("alice", run.ID); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if finishes.Load() != 1 || closes.Load() != 1 {
		t.Fatal(finishes.Load(), closes.Load())
	}
}

func TestPlatformProcessUsesAuthenticatedEphemeralBridge(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "bridge-fixture.mjs")
	code := `let s='';for await(const chunk of process.stdin)s+=chunk;const input=JSON.parse(s);
const b=input.platform.bridge;const reply=await fetch(b.url,{method:'POST',headers:{Authorization:'Bearer '+b.token,'Content-Type':'application/json'},body:JSON.stringify({name:'fixture',arguments:{value:'bound'},agent_id:'coordinator'})});
if(reply.status!==200||(await reply.json()).execution_id!=='actual')process.exit(2);
console.log(JSON.stringify({type:'report',agent_id:'coordinator',data:{text:'bridge used without publishing its credentials'}}));
console.log(JSON.stringify({type:'complete',data:{status:'completed'}}));`
	if err := os.WriteFile(script, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	input := bridgeInput(func(_ context.Context, call ToolCall) (*ToolReply, error) {
		called.Add(1)
		if call.Arguments["value"] != "bound" {
			t.Error(call)
		}
		return &ToolReply{ExecutionID: "actual", Content: []ToolContent{{Type: "text", Text: "done"}}}, nil
	})
	input.RunID = "fixture"
	input.Model = fixtureModel()
	var events []Event
	err = (&ProcessRuntime{Node: node, Script: script}).Run(context.Background(), dir, input, func(e Event) error { events = append(events, e); return nil })
	if err != nil || called.Load() != 1 || len(events) != 2 {
		t.Fatal(err, called.Load(), events)
	}
	if input.Platform.Bridge != nil {
		t.Fatal("ephemeral credential leaked into caller snapshot")
	}
}
