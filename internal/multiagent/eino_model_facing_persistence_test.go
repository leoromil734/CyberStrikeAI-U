package multiagent

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

func TestBuildEinoRunResultNeverPersistsRawAccumulationWithoutModelFacingTrace(t *testing.T) {
	raw := []schema.Message{*schema.ToolMessage(strings.Repeat("raw-tool-output", 1000), "call-1")}
	rawMsgs := make([]*schema.Message, len(raw))
	for i := range raw {
		rawMsgs[i] = &raw[i]
	}
	result := buildEinoRunResultFromAccumulated("deep", rawMsgs, nil, "", "", "empty", nil, true)
	if result.LastAgentTraceInput != "" {
		t.Fatalf("pre-model raw accumulation must not be persisted: %d bytes", len(result.LastAgentTraceInput))
	}

	modelFacing := []*schema.Message{schema.UserMessage("bounded-model-view")}
	result = buildEinoRunResultFromAccumulated("deep", rawMsgs, modelFacing, "ok", "", "empty", nil, false)
	if !strings.Contains(result.LastAgentTraceInput, "bounded-model-view") {
		t.Fatalf("model-facing trace missing: %s", result.LastAgentTraceInput)
	}
	if strings.Contains(result.LastAgentTraceInput, "raw-tool-output") {
		t.Fatal("raw accumulation leaked into persisted model-facing trace")
	}
	if !agent.IsModelFacingTraceJSON(result.LastAgentTraceInput) {
		t.Fatal("persisted model-facing trace is missing its version marker")
	}
}

func TestAppendTerminalToolPairsForTraceScopesAndBoundsTail(t *testing.T) {
	const maxToolBytes = 128
	hugeResult := strings.Repeat("terminal-tool-result-", 80)
	accumulated := []adk.Message{
		schema.UserMessage("raw-event-only-user"),
		schema.AssistantMessage("", []schema.ToolCall{{
			ID: "ignored-call",
			Function: schema.FunctionCall{
				Name:      "ignored_tool",
				Arguments: `{}`,
			},
		}}),
		schema.ToolMessage("unrelated-raw-result", "ignored-call"),
		schema.AssistantMessage("", []schema.ToolCall{{
			ID: "terminal-call",
			Function: schema.FunctionCall{
				Name:      "http_framework_test",
				Arguments: `{"url":"https://example.test"}`,
			},
		}}),
		schema.ToolMessage(hugeResult, "terminal-call", schema.WithToolName("http_framework_test")),
	}

	trace := appendTerminalToolPairsForTrace(
		[]adk.Message{schema.UserMessage("bounded-model-view")},
		accumulated,
		map[string]struct{}{"terminal-call": {}},
		maxToolBytes,
	)
	if len(trace) != 3 {
		t.Fatalf("trace messages=%d, want model snapshot plus one tool pair", len(trace))
	}
	if trace[0].Content != "bounded-model-view" {
		t.Fatalf("model-facing snapshot changed: %q", trace[0].Content)
	}
	if len(trace[1].ToolCalls) != 1 || trace[1].ToolCalls[0].ID != "terminal-call" {
		t.Fatalf("terminal assistant tool call missing: %#v", trace[1])
	}
	if trace[2].Role != schema.Tool || trace[2].ToolCallID != "terminal-call" {
		t.Fatalf("terminal tool result missing: %#v", trace[2])
	}
	if len(trace[2].Content) > maxToolBytes {
		t.Fatalf("terminal tool result exceeded bound: %d", len(trace[2].Content))
	}
	if !strings.Contains(trace[2].Content, "tool output truncated") {
		t.Fatalf("terminal tool result missing truncation marker: %q", trace[2].Content)
	}
	for _, msg := range trace {
		if msg == nil {
			continue
		}
		if strings.Contains(msg.Content, "raw-event-only-user") ||
			strings.Contains(msg.Content, "unrelated-raw-result") {
			t.Fatalf("unrelated raw accumulation leaked into trace: %#v", msg)
		}
	}
}

func TestAppendTerminalToolPairsForTracePreservesModelFacingResult(t *testing.T) {
	call := schema.ToolCall{
		ID: "terminal-call",
		Function: schema.FunctionCall{
			Name:      "http_framework_test",
			Arguments: `{}`,
		},
	}
	modelFacing := []adk.Message{
		schema.UserMessage("run"),
		schema.AssistantMessage("", []schema.ToolCall{call}),
		schema.ToolMessage("reduced-model-facing-result", "terminal-call"),
	}
	accumulated := []adk.Message{
		schema.AssistantMessage("", []schema.ToolCall{call}),
		schema.ToolMessage("raw-bridge-result", "terminal-call"),
	}

	trace := appendTerminalToolPairsForTrace(
		modelFacing,
		accumulated,
		map[string]struct{}{"terminal-call": {}},
		128,
	)
	if len(trace) != len(modelFacing) {
		t.Fatalf("existing model-facing pair was duplicated: %d messages", len(trace))
	}
	if trace[2].Content != "reduced-model-facing-result" {
		t.Fatalf("model-facing result was overwritten: %q", trace[2].Content)
	}
}
