package handler

import "testing"

func TestCoverageFactInflationSwitchesStrategyWithoutRenewingProgress(t *testing.T) {
	state := &finalizationContinuationState{}
	for i, count := range []int{197, 1021, 4786} {
		d := coverageDecision(count, "inventory still incomplete")
		d.CoverageEvidenceExecutions = 3
		if !observeFinalizationContinuation(d, state) {
			t.Fatalf("investigation stopped at %d: %+v", i, state)
		}
		state.recordContinuation(d)
	}
	if state.WorkMode != "classify_and_verify" || state.CoverageEvidenceHighWater != 3 || state.CoverageNoProgress != 2 || state.StopReason != "" {
		t.Fatalf("fact inflation must switch strategy, not count as evidence: %+v", state)
	}
}

func TestLargeInventoryContinuesClassificationNotPerURLRepair(t *testing.T) {
	state := &finalizationContinuationState{}
	d := coverageDecision(1501, "25006 additional independent discovery groups lack dispositions")
	d.CoverageRepairBlocked = true
	d.CoverageUnresolvedGroups = 25036
	if !observeFinalizationContinuation(d, state) || state.WorkMode != "classify_and_verify" || state.StopReason != "" {
		t.Fatalf("large inventory stopped substantive work: %+v", state)
	}
	if state.Attempts != 0 || d.Finalizable || d.CoverageUnresolvedGroups != 25036 {
		t.Fatal("strategy selection consumed a segment or changed coverage")
	}
}

func TestUnknownEvidenceCannotRenewProgressButCanInvestigate(t *testing.T) {
	state := &finalizationContinuationState{}
	for i := 0; i < 3; i++ {
		d := coverageDecision(1000+i, "gap")
		d.CoverageProgressKnown = false
		d.CoverageRepairBlocked = true
		d.CoverageEvidenceExecutions = 1000 + i
		if !observeFinalizationContinuation(d, state) || state.WorkMode != "classify_and_verify" || state.CoverageEvidenceHighWater != 0 {
			t.Fatalf("unknown evidence was trusted or investigation blocked: %+v", state)
		}
		state.recordContinuation(d)
	}
}
