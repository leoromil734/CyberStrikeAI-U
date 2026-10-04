package agentfinalizer

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func partialDeliveryFixture(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "partial.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	conv, err := db.CreateConversation("offline partial report", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	return db, conv.ID
}

func TestPartialDeliveryRetainsOriginalAndDoesNotUpgradeAssessment(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	original := "# 正式报告\n安全态势优秀，全部验证完成。"
	for _, status := range []string{StatusBlocked, StatusFailed, StatusCancelled, "timeout"} {
		d := Decision{ConversationID: cid, Status: status, CompletionReason: ReasonCoverageIncomplete, FinalText: original,
			MissingChecks: []string{"endpoint_count must equal 25735", "full original diagnostic"}, CoverageProgressKnown: true,
			CoverageInventoryGroups: 25735, CoverageMappedGroups: 1, CoverageUnresolvedGroups: 25734, CoverageRepairBlocked: true}
		got := PrepareStoppedDelivery(db, d)
		if !got.DeliveryAvailable || !got.RunTerminated || got.DeliveryKind != DeliveryKindPartialReport || got.Status != status || got.Finalizable || got.Finalized || got.EvidenceVerified {
			t.Fatalf("bad partial delivery: %+v", got)
		}
		if got.FinalText != original || strings.Join(got.MissingChecks, "|") != strings.Join(d.MissingChecks, "|") {
			t.Fatal("original report/checks lost")
		}
		for _, want := range []string{"阶段报告（评估未完成）", "25735", "25734", "尚无已登记漏洞", "不能据此认定目标整体安全", "不会自动启动"} {
			if !strings.Contains(got.DeliveryText, want) {
				t.Fatalf("missing %q", want)
			}
		}
		for _, unsafe := range []string{"安全态势优秀", "endpoint_count must equal", "full original diagnostic"} {
			if strings.Contains(got.DeliveryText, unsafe) {
				t.Fatalf("unverified prose/internal checks promoted: %q", unsafe)
			}
		}
		payload := ResponsePayload(got, nil)
		if payload["deliveryAvailable"] != true || payload["runTerminated"] != true || payload["deliveryText"] != got.DeliveryText || payload["finalized"] != false {
			t.Fatalf("delivery metadata lost: %+v", payload)
		}
	}
}

func TestPartialDeliveryRequiresStoppedRunAndNoPendingTools(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	base := Decision{ConversationID: cid, Status: StatusBlocked, CompletionReason: ReasonCoverageIncomplete}
	for _, status := range []string{"", StatusInProgress, StatusAwaitingHITL, StatusCompleted, "paused"} {
		d := base
		d.Status = status
		if got := PrepareStoppedDelivery(db, d); got.DeliveryAvailable || got.RunTerminated {
			t.Fatalf("accepted live/unknown state %s", status)
		}
	}
	for _, kind := range []string{"pending", "toolruns", "approval"} {
		d := base
		switch kind {
		case "pending":
			d.PendingExecutionIDs = []string{"not-yet-finished"}
		case "toolruns":
			d.PendingToolRuns = []string{"not-yet-finished"}
		case "approval":
			d.CompletionReason = ReasonAwaitingHITL
		}
		if got := PrepareStoppedDelivery(db, d); got.DeliveryAvailable {
			t.Fatalf("ignored %s", kind)
		}
	}
	for _, status := range []string{mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning} {
		if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "pending", ConversationID: cid, ToolName: "offline", Status: status, StartTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if got := PrepareStoppedDelivery(db, base); got.DeliveryAvailable || got.RunTerminated {
			t.Fatal("unlisted conversation tool was ignored")
		}
	}
	if got := PrepareStoppedDelivery(nil, base); got.DeliveryAvailable {
		t.Fatal("nil database must fail closed")
	}
	db.Close()
	if got := PrepareStoppedDelivery(db, base); got.DeliveryAvailable {
		t.Fatal("read failure must fail closed")
	}
}

func TestPartialDeliveryFindingsAreConversationScopedAndKeepStatus(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	other, err := db.CreateConversation("other", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []*database.Vulnerability{
		{ConversationID: cid, Title: "Awaiting triage", Severity: "info", Status: "open"},
		{ConversationID: other.ID, Title: "PRIVATE_OTHER_CONVERSATION", Severity: "critical", Status: "confirmed"},
	} {
		if _, err := db.CreateVulnerability(v); err != nil {
			t.Fatal(err)
		}
	}
	d := PrepareStoppedDelivery(db, Decision{ConversationID: cid, Status: StatusBlocked})
	if !strings.Contains(d.DeliveryText, "Awaiting triage") || !strings.Contains(d.DeliveryText, "登记状态：open") || strings.Contains(d.DeliveryText, "PRIVATE_OTHER_CONVERSATION") {
		t.Fatalf("incorrect scope/status: %s", d.DeliveryText)
	}
	if !strings.Contains(d.DeliveryText, "不将未知数量记为零") {
		t.Fatal("unknown inventory shown as zero")
	}
}

func assessmentCandidateForTest() string {
	return "# 评估报告\n\n## 风险概览与测试范围\n" + strings.Repeat("授权范围和测试概览说明。", 30) + "\n## 已确认发现与范围限制\n已确认发现与未完成限制均需证据核对。"
}

func TestSubmittedBookkeepingDoesNotResurrectEarlierDraft(t *testing.T) {
	trace, err := json.Marshal([]map[string]string{
		{"role": "user", "content": "current scope"},
		{"role": "assistant", "content": assessmentCandidateForTest()},
		{"role": "user", "content": multiagent.CoverageContinuationHeader},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := &multiagent.RunResult{ReportSubmitted: true, SubmittedReport: "覆盖计数已对齐。", LastAgentTraceInput: string(trace)}
	d := FromRunResult(nil, result, Input{})
	if d.Finalizable || d.FinalText != "覆盖计数已对齐。" || d.CompletionReason != ReasonIncompleteCandidate {
		t.Fatalf("exit was replaced by old report or bookkeeping promoted: %+v", d)
	}
}

func TestSubmissionLifecycleSurvivesBatchAndRobotWrappers(t *testing.T) {
	for _, mode := range []string{"batch", "robot"} {
		result := &multiagent.RunResult{Response: assessmentCandidateForTest(), ReportSubmissionRequired: true}
		d := FromRunResult(nil, result, Input{AgentMode: mode})
		if d.Finalizable || d.CompletionReason != ReasonReportNotSubmitted {
			t.Fatalf("wrapper lost root submission policy: %+v", d)
		}
	}
	empty := &multiagent.RunResult{Response: assessmentCandidateForTest(), ReportSubmitted: true, SubmittedReport: ""}
	if d := FromRunResult(nil, empty, Input{}); d.Finalizable || d.CompletionReason != ReasonEmptyResponse {
		t.Fatalf("empty exit resurrected draft: %+v", d)
	}
	timedOut := &multiagent.RunResult{Status: "timeout", ReportSubmitted: true, SubmittedReport: assessmentCandidateForTest()}
	if d := FromRunResult(nil, timedOut, Input{}); d.Finalizable || d.Status != "timeout" {
		t.Fatalf("exit upgraded timeout: %+v", d)
	}
}

func TestDeepReportSubmissionDoesNotBypassCoverageGate(t *testing.T) {
	report := assessmentCandidateForTest()
	for _, mode := range []string{"eino_deep", "eino_supervisor"} {
		d := Decide(nil, Input{Response: report, AgentMode: mode})
		if d.Finalizable || d.CompletionReason != ReasonReportNotSubmitted {
			t.Fatalf("unsubmitted report accepted: %+v", d)
		}
		result := &multiagent.RunResult{Response: "a longer draft", ReportSubmitted: true, SubmittedReport: report}
		d = FromRunResult(nil, result, Input{AgentMode: mode, RequireCoverageEvidence: true})
		if d.Finalizable || d.EvidenceVerified || d.FinalText != report || !d.ReportSubmitted || d.CompletionReason != ReasonCoverageIncomplete {
			t.Fatalf("exit bypassed coverage or lost report: %+v", d)
		}
	}
	// Plan-execute does not use a root native exit lifecycle.
	if d := Decide(nil, Input{Response: report, AgentMode: "eino_plan_execute"}); !d.Finalizable {
		t.Fatalf("plan-execute was forced to exit: %+v", d)
	}
}
