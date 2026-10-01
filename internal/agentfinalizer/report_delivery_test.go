package agentfinalizer

import (
	"encoding/json"
	"strings"
	"testing"

	"cyberstrike-ai/internal/multiagent"
)

func coverageRepairResult(t *testing.T, withReport bool) *multiagent.RunResult {
	t.Helper()
	msgs := []map[string]string{{"role": "user", "content": "评估 example.invalid"}}
	if withReport {
		msgs = append(msgs, map[string]string{"role": "assistant", "content": "## 风险概览\n\n未确认漏洞。\n\n## 资产覆盖\n\n" + strings.Repeat("证据已保留，未测试入口有明确范围限制。", 20) + "\n\n## 已验证结论\n\n匿名权限受限。\n\n## 负结果与限制\n\n第三方未测。"})
	}
	msgs = append(msgs, map[string]string{"role": "user", "content": multiagent.CoverageContinuationHeader})
	data, err := json.Marshal(msgs)
	if err != nil {
		t.Fatal(err)
	}
	return &multiagent.RunResult{Response: "覆盖计数已对齐。端点 3 个，风险单元 7 条。", LastAgentTraceInput: string(data), LastAgentTraceOutput: "覆盖计数已对齐。"}
}

func TestFromRunResultDeliversReportAfterCoveragePasses(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "active")
	result := coverageRepairResult(t, true)
	original := result.Response
	trace := result.LastAgentTraceInput
	in := Input{ConversationID: conversation, AssistantMessageID: message}
	d := FromRunResult(db, result, in)
	if d.Finalizable || d.CompletionReason != ReasonCoverageIncomplete || result.Response != original {
		t.Fatalf("report recovery bypassed open coverage: %+v", d)
	}
	persistCoverage(t, db, project, conversation, "passed")
	// Each continuation produces a fresh RunResult. Do not feed back the blocked
	// status from the previous segment as though it were this segment's status.
	result = coverageRepairResult(t, true)
	d = FromRunResult(db, result, in)
	if !d.Finalizable || !strings.Contains(d.FinalText, "## 风险概览") || !strings.HasSuffix(d.FinalText, original) {
		t.Fatalf("complete report replaced by repair notice: %+v", d)
	}
	if result.Response != d.FinalText || result.LastAgentTraceOutput != d.FinalText || result.LastAgentTraceInput != trace {
		t.Fatal("final response/trace output must match delivery without altering original trace")
	}
}

func TestFromRunResultRepairNoticeWithoutReportCannotFinalize(t *testing.T) {
	result := coverageRepairResult(t, false)
	d := FromRunResult(nil, result, Input{})
	if d.Finalizable || d.Status != StatusInProgress || d.CompletionReason != ReasonIncompleteCandidate || len(d.MissingChecks) == 0 || result.Finalized {
		t.Fatalf("bookkeeping notice incorrectly delivered: %+v", d)
	}
}

func TestFromRunResultReportCannotOverrideTerminalStates(t *testing.T) {
	for _, status := range []string{StatusCancelled, StatusFailed, StatusAwaitingHITL, StatusBlocked} {
		t.Run(status, func(t *testing.T) {
			result := coverageRepairResult(t, true)
			result.Status = status
			original := result.Response
			d := FromRunResult(nil, result, Input{})
			if d.Finalizable || d.Status != status || result.Response != original {
				t.Fatalf("report recovery changed terminal state: %+v", d)
			}
		})
	}
}
