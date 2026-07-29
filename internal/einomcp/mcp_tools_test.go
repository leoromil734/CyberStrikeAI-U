package einomcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
)

func TestUnknownToolReminderText(t *testing.T) {
	s := unknownToolReminderText("bad_tool")
	if !strings.Contains(s, "bad_tool") {
		t.Fatalf("expected requested name in message: %s", s)
	}
	if strings.Contains(s, "Tools currently available") {
		t.Fatal("unified message must not list tool names")
	}
}

func TestToolsFromDefinitionsNormalizesHyphenatedModelName(t *testing.T) {
	defs := []agent.Tool{{
		Type: "function",
		Function: agent.FunctionDefinition{
			Name:       "http-framework-test",
			Parameters: map[string]interface{}{"type": "object"},
		},
	}}
	tools, err := ToolsFromDefinitions(nil, nil, defs, nil, nil, nil, "supervisor")
	if err != nil {
		t.Fatalf("ToolsFromDefinitions: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("tool count = %d, want 1", len(tools))
	}
	info, err := tools[0].Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "http_framework_test" {
		t.Fatalf("model-facing name = %q", info.Name)
	}
	bridge, ok := tools[0].(*mcpBridgeTool)
	if !ok {
		t.Fatalf("tool type = %T", tools[0])
	}
	if bridge.name != "http-framework-test" || bridge.modelName != "http_framework_test" {
		t.Fatalf("bridge names = canonical %q model %q", bridge.name, bridge.modelName)
	}
}

func TestToolsFromDefinitionsRejectsNormalizedNameCollision(t *testing.T) {
	defs := []agent.Tool{
		{Type: "function", Function: agent.FunctionDefinition{Name: "a-b", Parameters: map[string]interface{}{"type": "object"}}},
		{Type: "function", Function: agent.FunctionDefinition{Name: "a_b", Parameters: map[string]interface{}{"type": "object"}}},
	}
	_, err := ToolsFromDefinitions(nil, nil, defs, nil, nil, nil, "supervisor")
	if err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("expected normalized name collision, got %v", err)
	}
}

func TestIsRepairableExecSyntaxFailure(t *testing.T) {
	tests := []struct {
		name   string
		result string
		want   bool
	}{
		{name: "shell syntax", result: `sh: 11: Syntax error: word unexpected (expecting ")")`, want: true},
		{name: "python syntax", result: `SyntaxError: unterminated string literal`, want: true},
		{name: "network failure", result: `curl: (7) Failed to connect to host`, want: false},
		{name: "permission failure", result: `sh: cannot create /root/x: Permission denied`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRepairableExecSyntaxFailure(tt.result); got != tt.want {
				t.Fatalf("isRepairableExecSyntaxFailure(%q) = %v, want %v", tt.result, got, tt.want)
			}
		})
	}
}

func TestMCPBridgeToolDecorateExecSyntaxFailure_OneRepairAttempt(t *testing.T) {
	holder := &ConversationHolder{}
	holder.Set("conv-repair")
	bridge := &mcpBridgeTool{name: "exec", holder: holder}
	args := `{"command":"python3 -c \"print(\"broken\")\""}`
	failure := ToolErrorPrefix + `命令执行失败: exit status 2
输出: sh: 1: Syntax error: word unexpected (expecting ")")`

	first := bridge.decorateExecSyntaxFailure(args, failure, nil)
	if !strings.Contains(first, "retryable: true") || !strings.Contains(first, "repair_attempt: 1/1") {
		t.Fatalf("first syntax failure should require one repair retry: %s", first)
	}

	second := bridge.decorateExecSyntaxFailure(args, failure, nil)
	if !strings.Contains(second, "retryable: false") || !strings.Contains(second, "repeated unchanged") {
		t.Fatalf("repeated syntax failure should exhaust repair budget: %s", second)
	}
}

func TestMCPBridgeToolDecorateExecHTTPParseFailure_RequiresDiagnosticRetry(t *testing.T) {
	holder := &ConversationHolder{}
	holder.Set("conv-http-parse")
	bridge := &mcpBridgeTool{name: "exec", holder: holder}
	args := `{"command":"curl -sS https://example.test/api | python3 -c 'import json,sys; print(json.load(sys.stdin))'"}`
	failure := ToolErrorPrefix + `命令执行失败: exit status 1
输出: json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)`

	first := bridge.decorateExecSyntaxFailure(args, failure, nil)
	if !strings.Contains(first, "retryable: true") || !strings.Contains(first, "repair_attempt: 1/1") {
		t.Fatalf("first HTTP parse failure should allow one diagnostic retry: %s", first)
	}
	for _, required := range []string{"HTTP status", "Content-Type", "bounded body preview", "http-framework-test"} {
		if !strings.Contains(first, required) {
			t.Fatalf("HTTP recovery missing %q: %s", required, first)
		}
	}

	second := bridge.decorateExecSyntaxFailure(args, failure, nil)
	if !strings.Contains(second, "retryable: false") || !strings.Contains(second, "repeated unchanged") {
		t.Fatalf("repeated HTTP parse failure should stop unchanged retries: %s", second)
	}
}

func TestMCPBridgeToolDecorateExecHTTPParseFailure_DoesNotMisclassifyTargetErrors(t *testing.T) {
	holder := &ConversationHolder{}
	holder.Set("conv-http-target-error")
	bridge := &mcpBridgeTool{name: "exec", holder: holder}
	args := `{"command":"curl -sS https://example.test/api"}`
	failure := ToolErrorPrefix + `命令执行失败: exit status 7
输出: curl: (7) Failed to connect to host`

	if got := bridge.decorateExecSyntaxFailure(args, failure, nil); got != failure {
		t.Fatalf("network failure without JSON parser must pass through unchanged: %s", got)
	}
}

func TestMCPBridgeToolDecorateExecSyntaxFailure_NonRetryablePassesThroughAndResets(t *testing.T) {
	holder := &ConversationHolder{}
	holder.Set("conv-reset")
	bridge := &mcpBridgeTool{name: "exec", holder: holder}
	syntaxArgs := `{"command":"python3 -c \"broken\""}`
	syntaxFailure := ToolErrorPrefix + `sh: 1: Syntax error: unterminated quoted string`
	networkFailure := ToolErrorPrefix + `命令执行失败: exit status 7
输出: curl: (7) Failed to connect`

	_ = bridge.decorateExecSyntaxFailure(syntaxArgs, syntaxFailure, nil)
	if got := bridge.decorateExecSyntaxFailure(`{"command":"curl https://example.test"}`, networkFailure, nil); got != networkFailure {
		t.Fatalf("non-syntax failure must pass through unchanged: %s", got)
	}

	again := bridge.decorateExecSyntaxFailure(syntaxArgs, syntaxFailure, nil)
	if !strings.Contains(again, "retryable: true") {
		t.Fatalf("non-syntax result should reset syntax repair budget: %s", again)
	}

	hardErr := errors.New("transport failed")
	if got := bridge.decorateExecSyntaxFailure(syntaxArgs, syntaxFailure, hardErr); got != syntaxFailure {
		t.Fatalf("hard invocation error must pass through unchanged: %s", got)
	}
}
