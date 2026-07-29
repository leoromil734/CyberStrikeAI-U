package multiagent

import (
	"context"
	"strings"
	"testing"
	"time"

	agenttrace "cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

type toolCallCompletionRaceAgent struct {
	notify          *einomcp.ToolInvokeNotifyHolder
	completeBefore  bool
	completionDelay time.Duration
}

func (a *toolCallCompletionRaceAgent) Name(context.Context) string { return "supervisor" }

func (a *toolCallCompletionRaceAgent) Description(context.Context) string {
	return "tool completion race test agent"
}

func (a *toolCallCompletionRaceAgent) Run(context.Context, *adk.AgentInput, ...adk.AgentRunOption) *adk.AsyncIterator[*adk.AgentEvent] {
	iterator, generator := adk.NewAsyncIteratorPair[*adk.AgentEvent]()
	complete := func() {
		a.notify.Fire("call-race", "http_framework_test", "supervisor", true, "framework result", nil)
	}
	go func() {
		defer generator.Close()
		if a.completeBefore {
			complete()
		}
		generator.Send(&adk.AgentEvent{
			AgentName: "supervisor",
			Output: &adk.AgentOutput{
				MessageOutput: &adk.MessageVariant{
					Message: schema.AssistantMessage("", []schema.ToolCall{{
						ID:   "call-race",
						Type: "function",
						Function: schema.FunctionCall{
							Name:      "http_framework_test",
							Arguments: `{"url":"https://example.test"}`,
						},
					}}),
					Role: schema.Assistant,
				},
			},
		})
	}()
	if !a.completeBefore {
		go func() {
			time.Sleep(a.completionDelay)
			complete()
		}()
	}
	return iterator
}

func TestRunEinoADKAgentLoopReconcilesToolCompletionOrdering(t *testing.T) {
	tests := []struct {
		name           string
		completeBefore bool
		delay          time.Duration
	}{
		{name: "completion before pending registration", completeBefore: true},
		{name: "completion after iterator end", delay: 25 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notify := einomcp.NewToolInvokeNotifyHolder()
			agent := &toolCallCompletionRaceAgent{
				notify:          notify,
				completeBefore:  tt.completeBefore,
				completionDelay: tt.delay,
			}
			result, err := runEinoADKAgentLoop(context.Background(), &einoADKRunLoopArgs{
				OrchMode:         "supervisor",
				OrchestratorName: "supervisor",
				ConversationID:   "tool-completion-race",
				ToolInvokeNotify: notify,
				DA:               agent,
			}, []adk.Message{schema.UserMessage("run tool")})
			if err != nil {
				t.Fatalf("runEinoADKAgentLoop: %v", err)
			}
			if result == nil {
				t.Fatal("missing run result")
			}
			trace := result.LastAgentTraceInput
			if !agenttrace.IsModelFacingTraceJSON(trace) {
				t.Fatalf("trace missing model-facing version marker: %s", trace)
			}
			traceMessages, parseErr := agenttrace.ParseTraceMessages(trace)
			if parseErr != nil {
				t.Fatalf("parse persisted trace: %v", parseErr)
			}
			var foundCall, foundResult bool
			for _, msg := range traceMessages {
				for _, tc := range msg.ToolCalls {
					if tc.ID == "call-race" {
						foundCall = true
					}
				}
				if msg.Role == "tool" && msg.ToolCallID == "call-race" && msg.Content == "framework result" {
					foundResult = true
				}
			}
			if !foundCall || !foundResult {
				t.Fatalf("trace missing paired tool result: %s", trace)
			}
			if strings.Contains(trace, "tool result state unknown") || strings.Contains(trace, "without an observable result") {
				t.Fatalf("completion was incorrectly flushed as failed: %s", trace)
			}
		})
	}
}
