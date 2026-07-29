package multiagent

import (
	"strings"
	"testing"
)

func TestIsEinoEmptyResponseResult(t *testing.T) {
	empty := &RunResult{
		Response: "(Eino ADK single-agent session completed but no assistant text was captured. Check process details or logs.) " +
			"（Eino ADK 单代理会话已完成，但未捕获到助手文本输出。请查看过程详情或日志。）",
	}
	if !IsEinoEmptyResponseResult(empty) {
		t.Fatal("expected empty placeholder response")
	}
	ok := &RunResult{Response: "扫描完成，发现 2 个开放端口。"}
	if IsEinoEmptyResponseResult(ok) {
		t.Fatalf("expected real response, got placeholder match")
	}
	if IsEinoEmptyResponseResult(nil) {
		t.Fatal("nil result should be false")
	}
}

func TestHasEinoResumeTrace(t *testing.T) {
	if HasEinoResumeTrace(nil) {
		t.Fatal("nil")
	}
	if HasEinoResumeTrace(&RunResult{LastAgentTraceInput: "[]"}) {
		t.Fatal("enable resume on empty trace")
	}
	if !HasEinoResumeTrace(&RunResult{LastAgentTraceInput: `[{"role":"user","content":"hi"}]`}) {
		t.Fatal("expected resume trace")
	}
}

func TestEinoResponseContinueInstruction(t *testing.T) {
	tests := []struct {
		name              string
		response          string
		preferFinalReport bool
		wantKind          string
		wantSnippet       string
	}{
		{
			name:        "empty response",
			response:    "(Eino session completed but no assistant text was captured. Check process details or logs.)",
			wantKind:    EinoResponseContinueKindEmpty,
			wantSnippet: "Auto resume",
		},
		{
			name:              "supervisor empty response",
			response:          "(Eino session completed but no assistant text was captured. Check process details or logs.)",
			preferFinalReport: true,
			wantKind:          EinoResponseContinueKindFinalReport,
			wantSnippet:       "Final report required",
		},
		{
			name:        "status only completion",
			response:    "所有阶段均为 passed，无未闭合候选，可以交付。",
			wantKind:    EinoResponseContinueKindFinalReport,
			wantSnippet: "Final report required",
		},
		{
			name: "complete report",
			response: `结论摘要：未确认高危漏洞。
风险概览：整体低风险。
资产覆盖账本：已覆盖主站与 API。
已确认发现及复现证据：无。
测试结果：已完成授权与输入验证。
负结果：未复现越权。
范围限制：第三方支付不在范围内。`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instruction, kind := EinoResponseContinueInstruction(&RunResult{Response: tt.response}, tt.preferFinalReport)
			if kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tt.wantKind)
			}
			if tt.wantSnippet == "" {
				if instruction != "" {
					t.Fatalf("unexpected instruction: %s", instruction)
				}
				return
			}
			if !strings.Contains(instruction, tt.wantSnippet) {
				t.Fatalf("instruction missing %q: %s", tt.wantSnippet, instruction)
			}
		})
	}
}

func TestEmptyResponseContinueMaxAttemptsFromConfig(t *testing.T) {
	if got := EmptyResponseContinueMaxAttemptsFromConfig(nil); got != defaultEmptyResponseContinueMaxAttempts {
		t.Fatalf("default: got %d want %d", got, defaultEmptyResponseContinueMaxAttempts)
	}
}
