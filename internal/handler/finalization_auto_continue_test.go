package handler

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/agentfinalizer"
)

func TestShouldAutoContinueAfterFinalizationReasons(t *testing.T) {
	cases := []struct {
		name    string
		d       agentfinalizer.Decision
		attempt int
		want    bool
	}{
		{"缺覆盖证据", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonCoverageIncomplete, Status: agentfinalizer.StatusInProgress}, 0, true},
		{"覆盖续跑有界", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonCoverageIncomplete}, finalizationCoverageMaxAttempts, false},
		{"覆盖有进展可超过旧两段", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonCoverageIncomplete}, finalizationAutoContinueMaxAttempts, true},
		{"缺执行证据", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonMissingEvidence}, 0, true},
		{"有工具执行未结束", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonPendingTools, Status: agentfinalizer.StatusInProgress}, 0, true},
		{"候选没说完", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonIncompleteCandidate, Status: agentfinalizer.StatusInProgress}, 0, true},
		{"上游错误正文不续跑", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonUpstreamErrorText, Status: agentfinalizer.StatusFailed}, 0, false},
		{"已可交付", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonVerified, Finalizable: true}, 0, false},
		{"达到续跑上限", agentfinalizer.Decision{CompletionReason: agentfinalizer.ReasonIncompleteCandidate}, finalizationAutoContinueMaxAttempts, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAutoContinueAfterFinalization(tc.d, tc.attempt); got != tc.want {
				t.Fatalf("shouldAutoContinueAfterFinalization(%+v, %d) = %v, want %v", tc.d, tc.attempt, got, tc.want)
			}
		})
	}
}

// errStreamDecodeStub 复现真实遇到的流式负载解码错误，应被判为可重试的上游故障。
type errStreamDecodeStub struct{}

func (errStreamDecodeStub) Error() string {
	return "failed to receive stream chunk: invalid character 'd' after array element"
}

// errLocalExecStub 本地工具失败，不是上游故障。
type errLocalExecStub struct{}

func (errLocalExecStub) Error() string { return "本地工具执行失败: exit status 1" }

func TestRunExecutionErrorMessageMarksRetryable(t *testing.T) {
	retryable := runExecutionErrorMessage(errStreamDecodeStub{})
	if !strings.Contains(retryable, "模型/上游接口暂时不可用") {
		t.Fatalf("可重试错误应提示上游不可用: %q", retryable)
	}
	plain := runExecutionErrorMessage(errLocalExecStub{})
	if !strings.Contains(plain, "执行失败") || strings.Contains(plain, "暂时不可用") {
		t.Fatalf("本地失败应保持执行失败文案: %q", plain)
	}
}
