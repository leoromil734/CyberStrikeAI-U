package handler

import (
	"strings"
	"testing"
)

func TestCoverageFactInflationDoesNotRenewProgress(t *testing.T) {
	state := &finalizationContinuationState{}
	for i, count := range []int{197, 1021, 4786} {
		d := coverageDecision(count, "inventory still incomplete")
		d.CoverageEvidenceExecutions = 3
		got := observeFinalizationContinuation(d, state)
		if got != (i < 2) {
			t.Fatalf("fact inflation counted as evidence at %d: %+v", i, state)
		}
		if got {
			state.Attempts++
		}
	}
	if !strings.Contains(state.StopReason, "独立执行证据") {
		t.Fatal(state.StopReason)
	}
}

func TestLargeInventoryStopsBeforeAnyAutoRepair(t *testing.T) {
	state := &finalizationContinuationState{}
	d := coverageDecision(1501, "25006 additional independent discovery groups lack dispositions")
	d.CoverageRepairBlocked = true
	d.CoverageUnresolvedGroups = 25036
	if observeFinalizationContinuation(d, state) || state.Attempts != 0 {
		t.Fatal("large inventory entered per-URL repair")
	}
	if !strings.Contains(state.StopReason, "25036") {
		t.Fatal("original unresolved count lost")
	}
	if got := finalizationStoppedDecision(d, state); got.Status != "blocked" || got.Finalizable {
		t.Fatal("incomplete inventory became success")
	}
}

func TestUnknownEvidenceCannotRenewProgress(t *testing.T) {
	state := &finalizationContinuationState{}
	for i := 0; i < 3; i++ {
		d := coverageDecision(1000+i, "gap")
		d.CoverageProgressKnown = false
		d.CoverageEvidenceExecutions = 1000 + i
		if got := observeFinalizationContinuation(d, state); got != (i < 2) {
			t.Fatalf("unknown evidence was trusted: %+v", state)
		}
		state.Attempts++
	}
}
