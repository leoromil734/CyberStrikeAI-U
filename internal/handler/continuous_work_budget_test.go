package handler

import (
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/agentfinalizer"
)

func TestCoverageWorkDoesNotSpendReportDeliveryAllowance(t *testing.T) {
	s := &finalizationContinuationState{}
	for i := 0; i < 12; i++ {
		d := coverageDecision(i, "real work still pending")
		d.CoverageEvidenceExecutions = i + 1
		if !observeFinalizationContinuation(d, s) {
			t.Fatalf("useful work stopped at the old eight-segment boundary: %+v", s)
		}
		s.recordContinuation(d)
	}
	if s.WorkAttempts != 12 || s.DeliveryAttempts != 0 {
		t.Fatalf("work spent report budget: %+v", s)
	}
	d := agentfinalizer.Decision{Status: agentfinalizer.StatusInProgress, CompletionReason: agentfinalizer.ReasonReportNotSubmitted}
	for i := 0; i < finalizationAutoContinueMaxAttempts; i++ {
		if !observeFinalizationContinuation(d, s) || s.WorkMode != "deliver_report" {
			t.Fatalf("report did not retain its own allowance: %+v", s)
		}
		s.recordContinuation(d)
	}
	if observeFinalizationContinuation(d, s) || !strings.Contains(s.StopReason, "报告收尾") {
		t.Fatalf("unbounded report retry: %+v", s)
	}
}

func TestCoverageStagnationWindowRequiresElapsedTimeWithoutProgress(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1000, "facts alone do not prove tests")
	d.CoverageEvidenceExecutions = 3
	// 首观察初始化停滞时钟（此时已有真实进展），不递增无进展计数。
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatalf("first observation stopped early: %+v", s)
	}
	s.recordContinuation(d)
	// 事实补写不重置时钟：89 分钟无新进展仍在窗口内，可以继续。
	ledgerOnly := d
	ledgerOnly.CoverageValidFacts = 500
	if !observeFinalizationContinuationAt(ledgerOnly, s, base.Add(89*time.Minute)) {
		t.Fatalf("stopped inside the stagnation window: %+v", s)
	}
	s.recordContinuation(d)
	// 达到 90 分钟停滞窗口：停止续跑，且停止原因说明时间窗语义。
	if observeFinalizationContinuationAt(ledgerOnly, s, base.Add(90*time.Minute)) {
		t.Fatalf("stagnation window did not stop the loop: %+v", s)
	}
	if !strings.Contains(s.StopReason, "停滞窗口") || !strings.Contains(s.StopReason, "未新增可核查进展") {
		t.Fatalf("stop reason lost the window semantics: %q", s.StopReason)
	}
}

func TestLedgerMappingDoesNotRenewStagnationClockButProgressDoes(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "still unfinished")
	d.CoverageEvidenceExecutions = 1
	d.CoverageInventoryGroups = 20
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("first observation stopped early")
	}
	s.recordContinuation(d)
	ledgerOnly := d
	ledgerOnly.CoverageMappedGroups = 5
	ledgerOnly.CoverageValidFacts = 500
	if !observeFinalizationContinuationAt(ledgerOnly, s, base.Add(89*time.Minute)) {
		t.Fatal("ledger mapping stopped the loop before the window elapsed")
	}
	s.recordContinuation(d)
	if observeFinalizationContinuationAt(ledgerOnly, s, base.Add(90*time.Minute)) || s.CoverageNoProgress == 0 {
		t.Fatalf("ledger mapping renewed a stalled run: %+v", s)
	}

	// 新的侦察来源执行（真实可核查进展）重置停滞时钟，窗口从新进展重新起算。
	s = &finalizationContinuationState{}
	d = coverageDecision(1, "still unfinished")
	d.CoverageEvidenceExecutions = 1
	d.CoverageInventoryGroups = 20
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("first observation stopped early")
	}
	s.recordContinuation(d)
	advanced := d
	advanced.CoverageEvidenceExecutions = 2
	if !observeFinalizationContinuationAt(advanced, s, base.Add(80*time.Minute)) || s.CoverageNoProgress != 0 {
		t.Fatalf("new execution evidence did not renew the clock: %+v", s)
	}
	if !s.LastProgressAt.Equal(base.Add(80 * time.Minute)) {
		t.Fatalf("last progress time not renewed: %v", s.LastProgressAt)
	}
	s.recordContinuation(d)
	// 原 90 分钟窗口不再适用于旧起点：仍可继续到新进展 + 90 分钟之前。
	if !observeFinalizationContinuationAt(advanced, s, base.Add(100*time.Minute)) {
		t.Fatalf("renewed clock stopped too early: %+v", s)
	}
	s.recordContinuation(d)
	// 新进展后 90 分钟到点停止（80 + 90 = 170 分钟）。
	if observeFinalizationContinuationAt(advanced, s, base.Add(170*time.Minute)) {
		t.Fatalf("renewed window did not stop at the window boundary: %+v", s)
	}

	// 段数安全上限仍兜底病态快段：达到上限即停止，即使刚有进展。
	s = &finalizationContinuationState{}
	d = coverageDecision(1, "still unfinished")
	d.CoverageEvidenceExecutions = 2
	s.WorkAttempts = finalizationCoverageMaxAttempts
	if observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("progress bypassed absolute work-segment guard")
	}
}

func TestStopSummaryNeverCopiesPhaseReport(t *testing.T) {
	report := "# 阶段报告（评估未完成）\n\n" + strings.Repeat("证据与未测范围。", 200)
	d := agentfinalizer.Decision{
		Status: agentfinalizer.StatusBlocked, CompletionReason: agentfinalizer.ReasonCoverageIncomplete,
		DeliveryAvailable: true, RunTerminated: true, DeliveryKind: agentfinalizer.DeliveryKindPartialReport,
		DeliveryText: report, CoverageProgressKnown: true, CoverageInventoryGroups: 17411, CoverageUnresolvedGroups: 17411,
	}
	summary := finalizationStopSummary(d)
	visible := finalizationBlockedMessage(d)
	if strings.Contains(summary, "阶段报告") || len([]rune(summary)) > 500 || !strings.Contains(summary, "coverage_incomplete") || !strings.Contains(summary, "17411") {
		t.Fatalf("diagnostic copied report or lost cause: %s", summary)
	}
	if visible != report {
		t.Fatal("assistant delivery no longer preserves the phase report")
	}
	long := &BatchTask{Status: BatchTaskStatusBlocked, Error: report}
	if strings.Contains(batchTaskErrorSummary(long), "# 阶段报告") {
		t.Fatal("historical report was copied into queue error")
	}
	parts := make([]string, 30)
	for i := range parts {
		parts[i] = strings.Repeat("任务原因 ", 40)
	}
	if len([]rune(boundedQueueError(parts))) > 4000 {
		t.Fatal("queue error is unbounded")
	}
}

// 回归护栏：未处置原始候选按披露处理。短报告不再因为它被误当「可执行的覆盖工作」
// 拉回账本循环，而是走报告收尾自己的预算。
func TestShortCandidateWithOpenInventoryUsesReportBudgetNotBookkeepingLoop(t *testing.T) {
	s := &finalizationContinuationState{}
	d := coverageDecision(5, "candidate is brief but tools can still progress")
	d.CompletionReason = agentfinalizer.ReasonIncompleteCandidate
	d.CoverageUnresolvedGroups = 200
	d.CoverageRepairBlocked = true
	d.CoverageEvidenceExecutions = 4
	if !observeFinalizationContinuation(d, s) || s.WorkMode != "deliver_report" {
		t.Fatalf("disclosed inventory re-entered a bookkeeping work phase: %+v", s)
	}
}
