package multiagent

import (
	"context"
	"cyberstrike-ai/internal/mcp"
	"testing"
)

func TestRunBudgetStopPreservesTraceAndBlocksSuccess(t *testing.T) {
	for _, cause := range []error{mcp.ErrFactWriteBudget, mcp.ErrCoverageRepairBudget} {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(cause)
		input := &RunResult{Status: "completed", Response: "model claims all covered", Finalized: true, EvidenceVerified: true, LastAgentTraceInput: "original trace", MCPExecutionIDs: []string{"original"}}
		result, err := applyRunBudgetStop(ctx, input, context.Canceled)
		if err != nil || result.Status != "blocked" || result.Finalized || result.EvidenceVerified {
			t.Fatalf("bad budget terminal: %+v %v", result, err)
		}
		if result.LastAgentTraceInput != "original trace" || len(result.MCPExecutionIDs) != 1 || result.CompletionReason != mcp.AgentRunBudgetStopReason(cause) {
			t.Fatal("lost evidence or stop reason")
		}
	}
}

func TestRunBudgetStopDoesNotMaskUserCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := applyRunBudgetStop(ctx, nil, context.Canceled)
	if result != nil || err != context.Canceled {
		t.Fatal("ordinary cancellation was changed")
	}
}
