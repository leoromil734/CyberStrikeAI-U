package handler

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"cyberstrike-ai/internal/mcp"
)

func TestRequestFactBudgetSurvivesSiblingSegments(t *testing.T) {
	run := newAgentRunDeadline(context.Background(), time.Now().Add(time.Hour))
	defer run.close()
	first, _, _, cancelFirst := run.newEinoSegment()
	if err := mcp.AdmitProjectFactWrite(first, 1); err != nil {
		t.Fatal(err)
	}
	cancelFirst()
	second, _, _, cancelSecond := run.newEinoSegment()
	defer cancelSecond()
	if err := mcp.AdmitProjectFactWrite(second, 9999); !errors.Is(err, mcp.ErrFactWriteBudget) {
		t.Fatalf("new segment reset write limit: %v", err)
	}
	if run.Context.Err() != nil || second.Err() != nil {
		t.Fatal("fact quota must not cancel the request root or report segment")
	}
}

func TestRepairBudgetTimerStopsInnerLoopWithoutFinalizerReturn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		run := newAgentRunDeadline(context.Background(), start.Add(10*time.Hour))
		defer run.close()
		first, _, _, cancelFirst := run.newEinoSegment()
		mcp.StartCoverageRepairBudget(first, 15*time.Minute)
		cancelFirst()
		second, _, _, cancelSecond := run.newEinoSegment()
		defer cancelSecond()
		mcp.StartCoverageRepairBudget(second, time.Hour)
		<-second.Done() // synctest advances virtual time, not a real sleep.
		if time.Since(start) != 15*time.Minute || !errors.Is(context.Cause(second), mcp.ErrCoverageRepairBudget) {
			t.Fatalf("repair clock renewed or stopped incorrectly: elapsed=%s cause=%v", time.Since(start), context.Cause(second))
		}
	})
}
