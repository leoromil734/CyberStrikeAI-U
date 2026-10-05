package handler

import (
	"strings"
	"testing"

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

func TestCoverageStagnationRequiresConsecutiveIndependentEvidenceAbsence(t *testing.T) {
	s := &finalizationContinuationState{}
	for i := 0; i <= finalizationCoverageStagnationLimit; i++ {
		d := coverageDecision(1000+i*1000, "facts alone do not prove tests")
		d.CoverageEvidenceExecutions = 3
		continued := observeFinalizationContinuation(d, s)
		if i < finalizationCoverageStagnationLimit {
			if !continued {
				t.Fatalf("stopped before strategy change could work: %+v", s)
			}
			s.recordContinuation(d)
		} else if continued || !strings.Contains(s.StopReason, "未新增可核查") {
			t.Fatalf("fact inflation renewed a stalled task: %+v", s)
		}
	}
}

func TestNewSourceBackedDispositionRenewsStagnationNotHardLimit(t *testing.T) {
	s := &finalizationContinuationState{}
	d := coverageDecision(1, "still unfinished")
	d.CoverageEvidenceExecutions = 1
	d.CoverageInventoryGroups = 20
	for i := 0; i < finalizationCoverageStagnationLimit; i++ {
		if !observeFinalizationContinuation(d, s) {
			t.Fatal("fixture stopped before new verified disposition")
		}
		s.recordContinuation(d)
	}
	d.CoverageMappedGroups = 1
	if !observeFinalizationContinuation(d, s) || s.CoverageNoProgress != 0 {
		t.Fatalf("source-backed progress was discarded: %+v", s)
	}
	s.recordContinuation(d)
	s.WorkAttempts = finalizationCoverageMaxAttempts
	d.CoverageMappedGroups = 2
	if observeFinalizationContinuation(d, s) {
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

func TestShortCandidateWithOpenInventoryStaysInWorkPhase(t *testing.T) {
	s := &finalizationContinuationState{Attempts: 12, WorkAttempts: 12, DeliveryAttempts: finalizationAutoContinueMaxAttempts}
	d := coverageDecision(5, "candidate is brief but tools can still progress")
	d.CompletionReason = agentfinalizer.ReasonIncompleteCandidate
	d.CoverageUnresolvedGroups = 200
	d.CoverageRepairBlocked = true
	d.CoverageEvidenceExecutions = 4
	if !observeFinalizationContinuation(d, s) || s.WorkMode != "classify_and_verify" {
		t.Fatalf("short prose hid executable work: %+v", s)
	}
}
