package mcp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func budgetContext() (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(context.Background())
	return WithAgentRunBudget(ctx, cancel), cancel
}

func TestFactWriteBudgetSharedAcrossParallelRoles(t *testing.T) {
	ctx, cancel := budgetContext()
	defer cancel(nil)
	defer CloseAgentRunBudget(ctx)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if AdmitProjectFactWrite(context.WithValue(ctx, "role", "fixture"), 32) == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 32 {
		t.Fatalf("admitted=%d, want exactly 32", admitted.Load())
	}
	if !errors.Is(context.Cause(ctx), ErrFactWriteBudget) {
		t.Fatal("whole run was not stopped with its budget reason", context.Cause(ctx))
	}
}

func TestFactWriteBudgetSurvivesContinuationAndLimitChanges(t *testing.T) {
	ctx, cancel := budgetContext()
	defer CloseAgentRunBudget(ctx)
	if err := AdmitProjectFactWrite(ctx, 2); err != nil {
		t.Fatal(err)
	}
	cancel(nil)
	next, nextCancel := context.WithCancelCause(context.WithoutCancel(ctx))
	defer nextCancel(nil)
	next = WithAgentRunBudget(next, nextCancel)
	if err := AdmitProjectFactWrite(next, 10000); err != nil {
		t.Fatal(err)
	}
	if err := AdmitProjectFactWrite(next, 10000); !errors.Is(err, ErrFactWriteBudget) {
		t.Fatalf("limit reset on continuation: %v", err)
	}
	if !errors.Is(context.Cause(next), ErrFactWriteBudget) {
		t.Fatal("cancel targeted old segment")
	}
	again, againCancel := context.WithCancelCause(context.WithoutCancel(next))
	defer againCancel(nil)
	again = WithAgentRunBudget(again, againCancel)
	if !errors.Is(context.Cause(again), ErrFactWriteBudget) {
		t.Fatal("exhausted run was revived")
	}
	fresh, freshCancel := budgetContext()
	defer freshCancel(nil)
	defer CloseAgentRunBudget(fresh)
	if err := AdmitProjectFactWrite(fresh, 2); err != nil {
		t.Fatalf("new explicit request inherited old budget: %v", err)
	}
}

func TestCoverageRepairTimerCannotBeRenewedAndCancelsCurrentSegment(t *testing.T) {
	ctx, cancel := budgetContext()
	defer CloseAgentRunBudget(ctx)
	StartCoverageRepairBudget(ctx, time.Hour)
	b := AgentRunBudgetFromContext(ctx)
	first := b.repairTimer
	cancel(nil)
	next, nextCancel := context.WithCancelCause(context.WithoutCancel(ctx))
	defer nextCancel(nil)
	next = WithAgentRunBudget(next, nextCancel)
	StartCoverageRepairBudget(next, 20*time.Hour)
	if b.repairTimer != first {
		t.Fatal("repair deadline renewed")
	}
	// Invoke the timer callback's stop operation without sleeping.
	b.stop(ErrCoverageRepairBudget)
	if !errors.Is(context.Cause(next), ErrCoverageRepairBudget) {
		t.Fatal("repair expiry failed to cancel current segment")
	}
}

func TestClosedBudgetDoesNotCancelLaterWork(t *testing.T) {
	ctx, cancel := budgetContext()
	defer cancel(nil)
	StartCoverageRepairBudget(ctx, time.Hour)
	CloseAgentRunBudget(ctx)
	AgentRunBudgetFromContext(ctx).stop(ErrCoverageRepairBudget)
	if ctx.Err() != nil {
		t.Fatal("closed timer cancelled a finished request")
	}
	if err := AdmitProjectFactWrite(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("closed budget admitted a detached write")
	}
}
