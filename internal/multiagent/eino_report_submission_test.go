package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/einomcp"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/prebuilt/deep"
	"github.com/cloudwego/eino/adk/prebuilt/supervisor"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// The model is mocked; Runner, ChatModelAgent, Deep/Supervisor and ExitTool are
// the real pinned Eino implementation, including framework-managed RunPath.
type reportSubmissionModel struct {
	mu       sync.Mutex
	messages []*schema.Message
	calls    int
	tools    []*schema.ToolInfo
}

func (m *reportSubmissionModel) Generate(_ context.Context, _ []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tools = model.GetCommonOptions(nil, opts...).Tools
	if m.calls >= len(m.messages) {
		return nil, errors.New("unexpected model call after scripted report submission")
	}
	msg := m.messages[m.calls]
	m.calls++
	return msg, nil
}

func (m *reportSubmissionModel) Stream(ctx context.Context, msgs []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}

func submissionToolCall(id, name, args string) *schema.Message {
	return schema.AssistantMessage("", []schema.ToolCall{{ID: id, Type: "function", Function: schema.FunctionCall{Name: name, Arguments: args}}})
}

func submissionExitCall(t *testing.T, report string) *schema.Message {
	t.Helper()
	args, err := json.Marshal(map[string]string{"final_result": report})
	if err != nil {
		t.Fatal(err)
	}
	return submissionToolCall("new-root-exit", "exit", string(args))
}

func submissionDeep(t *testing.T, m model.BaseChatModel, trace *modelFacingTraceHolder, children ...adk.Agent) adk.Agent {
	t.Helper()
	root, err := deep.New(context.Background(), &deep.Config{
		Name: "root", Description: "root test role", Instruction: "test root report submission",
		ChatModel: m, MaxIteration: 5, WithoutGeneralSubAgent: true, WithoutWriteTodos: true,
		ToolsConfig: deepToolsWithExit(adk.ToolsConfig{}), SubAgents: children,
		Handlers: []adk.ChatModelAgentMiddleware{newModelFacingTraceMiddleware(trace)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func submissionRun(t *testing.T, mode string, root adk.Agent, trace *modelFacingTraceHolder, history []adk.Message) (*RunResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return runEinoADKAgentLoop(ctx, &einoADKRunLoopArgs{
		OrchMode: mode, OrchestratorName: "root", ConversationID: "report-submission-test",
		DA: root, ModelFacingTrace: trace, EmptyResponseMessage: "empty", ToolMaxBytes: 256,
	}, history)
}

func TestRunEinoADKRootExitSubmission(t *testing.T) {
	for _, mode := range []string{"deep", "supervisor"} {
		t.Run(mode, func(t *testing.T) {
			report := "\n" + einoTestReport(5) + "\n"
			call := submissionExitCall(t, report)
			call.Content = einoTestReport(80) // A much longer draft must not win.
			m := &reportSubmissionModel{messages: []*schema.Message{call}}
			trace := newModelFacingTraceHolder()
			var root adk.Agent
			if mode == "deep" {
				root = submissionDeep(t, m, trace)
			} else {
				chat, err := adk.NewChatModelAgent(context.Background(), &adk.ChatModelAgentConfig{
					Name: "root", Description: "supervisor", Model: m, Exit: &adk.ExitTool{},
					Handlers: []adk.ChatModelAgentMiddleware{newModelFacingTraceMiddleware(trace)},
				})
				if err != nil {
					t.Fatal(err)
				}
				root, err = supervisor.New(context.Background(), &supervisor.Config{Supervisor: chat})
				if err != nil {
					t.Fatal(err)
				}
			}
			old := einoTestReport(90)
			out, err := submissionRun(t, mode, root, trace, []adk.Message{
				schema.UserMessage("current user request"), schema.AssistantMessage(old, nil),
				submissionToolCall("old-exit", "exit", `{"final_result":"old submitted report"}`),
				historicalExitMsg("old submitted report", "old-exit"),
			})
			if err != nil || out == nil {
				t.Fatalf("run: %v, result=%#v", err, out)
			}
			if !out.ReportSubmitted || out.SubmittedReport != report || out.Response != strings.TrimSpace(report) {
				t.Fatalf("live root exit not authoritative: %#v", out)
			}
			if out.Finalized || out.EvidenceVerified || out.Status == "completed" || m.calls != 1 {
				t.Fatalf("exit must stop the model, not assert success: %#v calls=%d", out, m.calls)
			}
			var persisted []*schema.Message
			if err := json.Unmarshal([]byte(out.LastAgentTraceInput), &persisted); err != nil {
				t.Fatal(err)
			}
			var keptDraft, keptExit bool
			for _, msg := range persisted {
				keptDraft = keptDraft || msg.Content == old
				keptExit = keptExit || (msg.ToolCallID == "new-root-exit" && msg.Extra[rootExitReportExtraKey] == true)
			}
			if !keptDraft || !keptExit {
				t.Fatalf("model-facing history or terminal root exit lost: %s", out.LastAgentTraceInput)
			}
			var hasExit bool
			for _, info := range m.tools {
				hasExit = hasExit || info.Name == "exit"
			}
			if !hasExit {
				t.Fatal("native exit was not visible to the model")
			}
		})
	}
}

func TestRunEinoADKHistoryCannotSubmit(t *testing.T) {
	for _, boundary := range []string{"", CoverageContinuationHeader, "a genuinely new user request"} {
		t.Run(boundary, func(t *testing.T) {
			trace := newModelFacingTraceHolder()
			m := &reportSubmissionModel{messages: []*schema.Message{schema.AssistantMessage("", nil)}}
			root := submissionDeep(t, m, trace)
			history := []adk.Message{schema.UserMessage("old request"),
				submissionToolCall("old-exit", "exit", `{"final_result":"old report"}`),
				historicalExitMsg(einoTestReport(40), "old-exit")}
			if boundary != "" {
				history = append(history, schema.UserMessage(boundary))
			}
			out, err := submissionRun(t, "deep", root, trace, history)
			if err != nil || out == nil {
				t.Fatalf("run: %v", err)
			}
			if out.ReportSubmitted || out.SubmittedReport != "" || out.Response != "empty" {
				t.Fatalf("history was treated as a current submission: %#v", out)
			}
		})
	}
}

func TestRunEinoADKChildExitDoesNotSubmitOrStopParent(t *testing.T) {
	for _, childName := range []string{"specialist", "root"} {
		t.Run(childName, func(t *testing.T) {
			childModel := &reportSubmissionModel{messages: []*schema.Message{submissionExitCall(t, einoTestReport(40))}}
			child, err := adk.NewChatModelAgent(context.Background(), &adk.ChatModelAgentConfig{
				Name: childName, Description: "child role", Model: childModel, Exit: &adk.ExitTool{},
			})
			if err != nil {
				t.Fatal(err)
			}
			args, _ := json.Marshal(map[string]string{"subagent_type": childName, "description": "only the assigned subtask"})
			parentModel := &reportSubmissionModel{messages: []*schema.Message{
				submissionToolCall("delegate", "task", string(args)), schema.AssistantMessage("parent continues with a draft", nil),
			}}
			trace := newModelFacingTraceHolder()
			out, err := submissionRun(t, "deep", submissionDeep(t, parentModel, trace, child), trace, []adk.Message{schema.UserMessage("current")})
			if err != nil || out == nil {
				t.Fatalf("run: %v", err)
			}
			if out.ReportSubmitted || out.SubmittedReport != "" || out.Response != "parent continues with a draft" || parentModel.calls != 2 {
				t.Fatalf("child exit escaped its scope: %#v, parent calls=%d", out, parentModel.calls)
			}
		})
	}
}

func TestRunEinoADKSupervisorExitAfterTransfer(t *testing.T) {
	ctx := context.Background()
	trace := newModelFacingTraceHolder()
	report := einoTestReport(5)
	parentModel := &reportSubmissionModel{messages: []*schema.Message{
		submissionToolCall("delegate", "transfer_to_agent", `{"agent_name":"specialist"}`), submissionExitCall(t, report),
	}}
	parent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name: "root", Description: "supervisor", Model: parentModel, Exit: &adk.ExitTool{},
		Handlers: []adk.ChatModelAgentMiddleware{newModelFacingTraceMiddleware(trace)},
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name: "specialist", Description: "child", Model: &reportSubmissionModel{messages: []*schema.Message{schema.AssistantMessage("subtask evidence", nil)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := supervisor.New(ctx, &supervisor.Config{Supervisor: parent, SubAgents: []adk.Agent{child}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := submissionRun(t, "supervisor", root, trace, []adk.Message{schema.UserMessage("current")})
	if err != nil || out == nil || !out.ReportSubmitted || out.SubmittedReport != report {
		t.Fatalf("root exit after native transfer not accepted: %#v, err=%v", out, err)
	}
}

func TestRunEinoADKFailedOrUnexecutedExitCannotSubmit(t *testing.T) {
	for _, soft := range []bool{false, true} {
		t.Run(map[bool]string{false: "hard error", true: "soft error"}[soft], func(t *testing.T) {
			cfg := deepToolsWithExit(adk.ToolsConfig{})
			if soft {
				cfg.ToolCallMiddlewares = []compose.ToolMiddleware{softRecoveryToolMiddleware()}
			}
			root, err := deep.New(context.Background(), &deep.Config{
				Name: "root", Description: "root", Instruction: "test", WithoutGeneralSubAgent: true, WithoutWriteTodos: true,
				ChatModel:   &reportSubmissionModel{messages: []*schema.Message{submissionToolCall("bad-exit", "exit", `{"final_result": {"invalid":"not a string"}}`)}},
				ToolsConfig: cfg,
			})
			if err != nil {
				t.Fatal(err)
			}
			out, runErr := submissionRun(t, "deep", root, newModelFacingTraceHolder(), []adk.Message{schema.UserMessage("current")})
			if !soft && runErr == nil {
				t.Fatal("invalid native exit arguments must fail")
			}
			if out != nil && (out.ReportSubmitted || out.SubmittedReport != "" || strings.Contains(out.Response, "invalid")) {
				t.Fatalf("failed exit was submitted: %#v, err=%v", out, runErr)
			}
		})
	}
	for _, reply := range []*schema.Message{submissionExitCall(t, einoTestReport(5)), schema.AssistantMessage(deliveryTestReport(), nil)} {
		root, err := adk.NewChatModelAgent(context.Background(), &adk.ChatModelAgentConfig{
			Name: "root", Description: "no exit registered", Model: &reportSubmissionModel{messages: []*schema.Message{reply}},
		})
		if err != nil {
			t.Fatal(err)
		}
		out, err := submissionRun(t, "deep", root, newModelFacingTraceHolder(), []adk.Message{schema.UserMessage("current")})
		if err != nil || out == nil || out.ReportSubmitted || out.SubmittedReport != "" {
			t.Fatalf("unexecuted arguments or ordinary assistant report submitted: %#v, err=%v", out, err)
		}
		if len(reply.ToolCalls) != 0 && out.Response != "empty" {
			t.Fatal("unexecuted exit arguments became the report")
		}
	}
}

func TestEinoReportSubmissionRejectsBadEventEvidence(t *testing.T) {
	ctx := context.Background()
	root, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name: "root", Description: "root", Model: &reportSubmissionModel{messages: []*schema.Message{submissionExitCall(t, "report")}}, Exit: &adk.ExitTool{},
	})
	if err != nil {
		t.Fatal(err)
	}
	iter := adk.NewRunner(ctx, adk.RunnerConfig{Agent: root}).Query(ctx, "current")
	var exit *adk.AgentEvent
	for {
		ev, ok := iter.Next()
		if !ok {
			break
		}
		if ev.Action != nil && ev.Action.Exit {
			exit = ev
		}
	}
	if exit == nil {
		t.Fatal("real ADK exit event missing")
	}
	for _, kind := range []string{"no action", "no path", "nested same name", "error event", "stream error", "error result", "assistant arguments"} {
		t.Run(kind, func(t *testing.T) {
			ev := *exit
			msg := *exit.Output.MessageOutput.Message
			var recvErr error
			switch kind {
			case "no action":
				ev.Action = nil
			case "no path":
				ev.RunPath = nil
			case "nested same name":
				ev.RunPath = append(append([]adk.RunStep(nil), ev.RunPath...), ev.RunPath[0])
			case "error event":
				ev.Err = errors.New("tool failed")
			case "stream error":
				recvErr = errors.New("incomplete tool stream")
			case "error result":
				msg.Content = einomcp.ToolErrorPrefix + "not a report"
			case "assistant arguments":
				msg = *submissionExitCall(t, "unexecuted report")
			}
			s := newEinoReportSubmission("root", "deep")
			s.observe(&ev, &msg, recvErr)
			if s.submitted || s.report != "" {
				t.Fatalf("bad event was accepted: %s", kind)
			}
		})
	}
}

func TestRunEinoADKExitReportBypassesReductionTruncation(t *testing.T) {
	ctx := context.Background()
	backend, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	red, err := buildReductionMiddleware(ctx, config.MultiAgentEinoMiddlewareConfig{
		ReductionRootDir: t.TempDir(), ReductionMaxLengthForTrunc: 32,
	}, "", "report-test", backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := einoTestReport(100)
	root, err := deep.New(ctx, &deep.Config{
		Name: "root", Description: "root", Instruction: "test", WithoutGeneralSubAgent: true, WithoutWriteTodos: true,
		ChatModel:   &reportSubmissionModel{messages: []*schema.Message{submissionExitCall(t, report)}},
		ToolsConfig: deepToolsWithExit(adk.ToolsConfig{}), Handlers: []adk.ChatModelAgentMiddleware{red},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := submissionRun(t, "deep", root, newModelFacingTraceHolder(), []adk.Message{schema.UserMessage("current")})
	if err != nil || out == nil || !out.ReportSubmitted || out.SubmittedReport != report || out.Response != strings.TrimSpace(report) {
		t.Fatalf("exit report was reduced into a file notice: %#v err=%v", out, err)
	}
}

func TestDeepExitConfigurationDoesNotMutateSharedTools(t *testing.T) {
	shared := adk.ToolsConfig{ReturnDirectly: map[string]bool{"other": true}}
	deepCfg := deepToolsWithExit(shared)
	if len(shared.Tools) != 0 || shared.ReturnDirectly["exit"] || !shared.ReturnDirectly["other"] {
		t.Fatal("deep exit leaked into another role's tool configuration")
	}
	if len(deepCfg.Tools) != 1 || !deepCfg.ReturnDirectly["exit"] || !deepCfg.ReturnDirectly["other"] {
		t.Fatal("deep exit configuration does not mirror native Exit configuration")
	}
}
