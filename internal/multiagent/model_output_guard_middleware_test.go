package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

func guardedAssistant(arguments, finishReason string) adk.Message {
	msg := assistantToolCallsMsg("", "call-1")
	msg.ToolCalls[0].Function.Name = "exec"
	msg.ToolCalls[0].Function.Arguments = arguments
	msg.ResponseMeta = &schema.ResponseMeta{
		FinishReason: finishReason,
		Usage: &schema.TokenUsage{
			CompletionTokens:        99,
			CompletionTokensDetails: schema.CompletionTokensDetails{ReasoningTokens: 33},
		},
	}
	return msg
}

func runModelOutputGuard(t *testing.T, messages []adk.Message, cfg config.MultiAgentEinoMiddlewareConfig) (*adk.ChatModelAgentState, error) {
	t.Helper()
	mw := newModelOutputGuardMiddleware(&cfg, nil, "test").(*modelOutputGuardMiddleware)
	_, state, err := mw.AfterModelRewriteState(context.Background(), &adk.ChatModelAgentState{Messages: messages}, &adk.ModelContext{})
	return state, err
}

func TestModelOutputGuardRejectsTruncatedToolCallBeforeExecution(t *testing.T) {
	original := `{"command":"secret-token-should-not-survive`
	state, err := runModelOutputGuard(t, []adk.Message{schema.UserMessage("run"), guardedAssistant(original, "length")}, config.MultiAgentEinoMiddlewareConfig{})
	if err != nil {
		t.Fatal(err)
	}
	got := state.Messages[len(state.Messages)-1].ToolCalls[0].Function.Arguments
	if strings.Contains(got, "secret-token") || !strings.Contains(got, modelOutputRecoveryKey) {
		t.Fatalf("unsafe arguments were not replaced: %q", got)
	}
	marker, ok := modelOutputRecoveryFromToolCall(state.Messages[len(state.Messages)-1].ToolCalls[0])
	if !ok || marker.Reason != "output_limit" || marker.CompletionTokens != 99 || marker.ReasoningTokens != 33 {
		t.Fatalf("unexpected recovery marker: %+v ok=%v", marker, ok)
	}
}

func TestModelOutputGuardRejectsInvalidJSONShapes(t *testing.T) {
	for _, arguments := range []string{"", `[]`, `{"command":`} {
		t.Run(arguments, func(t *testing.T) {
			state, err := runModelOutputGuard(t, []adk.Message{guardedAssistant(arguments, "tool_calls")}, config.MultiAgentEinoMiddlewareConfig{})
			if err != nil {
				t.Fatal(err)
			}
			marker, ok := modelOutputRecoveryFromToolCall(state.Messages[0].ToolCalls[0])
			if !ok || marker.Reason != "invalid_tool_arguments_json" {
				t.Fatalf("arguments=%q marker=%+v ok=%v", arguments, marker, ok)
			}
		})
	}
}

func TestGeneratedToolCallSizeBoundaries(t *testing.T) {
	cfg := modelOutputGuardConfig{maxToolArgumentsBytes: 128, maxShellCommandBytes: 16, maxRepairAttempts: 1}
	call := schema.ToolCall{Function: schema.FunctionCall{Name: "exec", Arguments: `{"command":"1234567890123456"}`}}
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "" {
		t.Fatalf("shell boundary should pass: %s", reason)
	}
	call.Function.Arguments = `{"command":"12345678901234567"}`
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "shell_command_too_large" {
		t.Fatalf("shell overflow reason=%q", reason)
	}
	call.Function.Name = "other"
	call.Function.Arguments = `{"value":"` + strings.Repeat("x", 116) + `"}`
	if len(call.Function.Arguments) != 128 {
		t.Fatalf("test fixture length=%d", len(call.Function.Arguments))
	}
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "" {
		t.Fatalf("generic boundary should pass: %q", reason)
	}
	call.Function.Arguments = `{"value":"` + strings.Repeat("x", 200) + `"}`
	if reason, _ := validateGeneratedToolCall(call, cfg); reason != "tool_arguments_too_large" {
		t.Fatalf("generic overflow reason=%q", reason)
	}
}

func TestGeneratedToolCallRejectsOversizedInlineHeredoc(t *testing.T) {
	cfg := modelOutputGuardConfig{maxToolArgumentsBytes: 1 << 20, maxShellCommandBytes: 1 << 20, maxInlineScriptBytes: 256, maxRepairAttempts: 1}
	call := func(command string) schema.ToolCall {
		encoded, err := json.Marshal(map[string]any{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		return schema.ToolCall{Function: schema.FunctionCall{Name: "exec", Arguments: string(encoded)}}
	}

	// A short heredoc stays legal: writing a two-line script to disk first gains
	// nothing, and rejecting it would add a round trip to ordinary work.
	short := "python3 - <<'PY'\nprint('hi')\nPY"
	if reason, _ := validateGeneratedToolCall(call(short), cfg); reason != "" {
		t.Fatalf("short heredoc must stay allowed, got %q", reason)
	}

	// An oversized inline program is what the rule exists for.
	big := "python3 - <<'PY'\n" + strings.Repeat("x = 1\n", 120) + "PY"
	if reason, _ := validateGeneratedToolCall(call(big), cfg); reason != "inline_script_too_large" {
		t.Fatalf("oversized inline script must be rejected, got %q", reason)
	}

	// The same body via write_file + short command is exactly what is wanted.
	shortCommand := "python3 /tmp/workspace/scripts/scan.py"
	if reason, _ := validateGeneratedToolCall(call(shortCommand), cfg); reason != "" {
		t.Fatalf("referencing a written file must pass, got %q", reason)
	}

	// Non-exec tools are unaffected.
	other := schema.ToolCall{Function: schema.FunctionCall{Name: "read_file", Arguments: string(mustJSON(t, map[string]any{"command": big}))}}
	if reason, _ := validateGeneratedToolCall(other, cfg); reason != "" {
		t.Fatalf("non-exec tools must not be judged by the heredoc rule, got %q", reason)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestInlineScriptBodyBytesMeasuresOnlyHeredocBodies(t *testing.T) {
	// 期望值等于"把 heredoc 正文原样写进文件后文件的大小"：每个正文行都含行尾换行，
	// 终止符本身不算。用这个口径是因为阈值判断要稳定——正文与终止符之间多一个
	// 空行是排版习惯，不该让同一段脚本在阈值上下翻转。
	cases := map[string]int{
		"echo hello":                            0,
		"python3 -c 'print(1)'":                 0,
		"ls | wc -l":                            0,
		"cat <<EOF\none\ntwo\nEOF":              8, // "one\n" + "two\n"
		"cat <<-'EOF'\n\tone\n\tEOF":            5, // "\tone\n"
		"cat <<EOF\nbody\nEOF\necho after":      5, // "body\n"
		"ssh host <<'REMOTE'\nline one\nREMOTE": 9, // "line one\n"
		"cmd <<< 'here-string'":                 0,
		"cat <<EOF\nunterminated":               13, // "unterminated" 无行尾换行，未闭合仍全部计入
		"cat <<EOF\nouter\nEOF":                 6,  // "outer\n"
	}
	for command, want := range cases {
		if got := inlineScriptBodyBytes(command); got != want {
			t.Errorf("inlineScriptBodyBytes(%q) = %d, want %d", command, got, want)
		}
	}
}

func TestModelOutputGuardAllowsOneRepairThenFails(t *testing.T) {
	first, err := runModelOutputGuard(t, []adk.Message{guardedAssistant(`{"command":`, "tool_calls")}, config.MultiAgentEinoMiddlewareConfig{})
	if err != nil {
		t.Fatal(err)
	}
	toolCall := first.Messages[0].ToolCalls[0]
	recoveryResult := schema.ToolMessage(modelOutputRejectedResultPrefix+" retry", toolCall.ID)
	secondMessages := append(first.Messages, recoveryResult, guardedAssistant(`{"command":`, "tool_calls"))
	_, err = runModelOutputGuard(t, secondMessages, config.MultiAgentEinoMiddlewareConfig{})
	var rejected *modelOutputRejectedError
	if !errors.As(err, &rejected) || rejected.Repairable || rejected.RepairAttempt != 2 {
		t.Fatalf("second rejection should be terminal: %#v", err)
	}
}

func TestModelOutputGuardNoToolLengthIsRepairableOnce(t *testing.T) {
	truncated := schema.AssistantMessage("partial", nil)
	truncated.ResponseMeta = &schema.ResponseMeta{FinishReason: "length"}
	_, err := runModelOutputGuard(t, []adk.Message{schema.UserMessage("answer"), truncated}, config.MultiAgentEinoMiddlewareConfig{})
	var rejected *modelOutputRejectedError
	if !errors.As(err, &rejected) || !rejected.Repairable {
		t.Fatalf("first no-tool length should be repairable: %#v", err)
	}
	_, err = runModelOutputGuard(t, []adk.Message{schema.UserMessage("answer"), schema.UserMessage(modelOutputRepairInstruction), truncated}, config.MultiAgentEinoMiddlewareConfig{})
	if !errors.As(err, &rejected) || rejected.Repairable || rejected.RepairAttempt != 2 {
		t.Fatalf("second no-tool length should fail: %#v", err)
	}
}

func TestModelOutputExecutionGuardNeverCallsTool(t *testing.T) {
	markerJSON := `{"` + modelOutputRecoveryKey + `":{"reason":"output_limit","repair_attempt":1}}`
	called := false
	mw := modelOutputExecutionGuardMiddleware().Invokable
	endpoint := mw(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		called = true
		return &compose.ToolOutput{Result: "executed"}, nil
	})
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "exec", Arguments: markerJSON})
	if err != nil || called || out == nil || !strings.HasPrefix(out.Result, modelOutputRejectedResultPrefix) {
		t.Fatalf("guard failed: called=%v out=%+v err=%v", called, out, err)
	}
}

func TestModelOutputExecutionGuardBlocksStreamableTool(t *testing.T) {
	markerJSON := `{"` + modelOutputRecoveryKey + `":{"reason":"shell_command_too_large","repair_attempt":1}}`
	called := false
	endpoint := modelOutputExecutionGuardMiddleware().Streamable(func(context.Context, *compose.ToolInput) (*compose.StreamToolOutput, error) {
		called = true
		return &compose.StreamToolOutput{Result: schema.StreamReaderFromArray([]string{"executed"})}, nil
	})
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "execute", Arguments: markerJSON})
	if err != nil || called || out == nil {
		t.Fatalf("stream guard failed: called=%v out=%+v err=%v", called, out, err)
	}
	result, recvErr := out.Result.Recv()
	if recvErr != nil || !strings.HasPrefix(result, modelOutputRejectedResultPrefix) {
		t.Fatalf("unexpected stream result=%q err=%v", result, recvErr)
	}
}

func TestModelOutputExecutionGuardAllowsNormalTool(t *testing.T) {
	called := false
	endpoint := modelOutputExecutionGuardMiddleware().Invokable(func(context.Context, *compose.ToolInput) (*compose.ToolOutput, error) {
		called = true
		return &compose.ToolOutput{Result: "executed"}, nil
	})
	out, err := endpoint(context.Background(), &compose.ToolInput{Name: "exec", Arguments: `{"command":"true"}`})
	if err != nil || !called || out == nil || out.Result != "executed" {
		t.Fatalf("normal tool should execute: called=%v out=%+v err=%v", called, out, err)
	}
}

func TestModelOutputRejectedErrorIsNotTransient(t *testing.T) {
	if isEinoTransientRunError(&modelOutputRejectedError{Reason: "output_limit", Repairable: true}) {
		t.Fatal("model output rejection must not use network backoff")
	}
}
