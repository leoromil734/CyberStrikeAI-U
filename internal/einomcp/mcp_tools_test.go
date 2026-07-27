package einomcp

import (
	"errors"
	"strings"
	"testing"
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
