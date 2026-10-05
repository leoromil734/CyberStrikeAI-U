package handler

import (
	"context"
	"errors"
	"time"

	"cyberstrike-ai/internal/mcp"
)

// Batch and interactive requests share one absolute lifetime. Continuations do
// not renew it; explicit user cancellation and per-tool limits remain effective.
const defaultAgentRunTimeout = 600 * time.Minute

// agentRunDeadline owns the budget and terminal cancellation for one user request.
// Continuations create sibling segments beneath Context, never a new deadline.
// Only the request entry point may detach the HTTP context (for SSE reconnects).
type agentRunDeadline struct {
	context.Context
	cancel        context.CancelCauseFunc
	timeoutCancel context.CancelFunc
}

func newAgentRunDeadline(parent context.Context, deadline time.Time) *agentRunDeadline {
	deadlineCtx, timeoutCancel := context.WithDeadline(parent, deadline)
	runCtx, cancel := context.WithCancelCause(deadlineCtx)
	runCtx = mcp.WithAgentRunBudget(runCtx, cancel)
	return &agentRunDeadline{Context: runCtx, cancel: cancel, timeoutCancel: timeoutCancel}
}

// newSegment isolates cleanup and the supplied interrupt cause to one segment.
// Other explicit cancellation causes terminate the request, including a user
// stop delivered through a callback captured before the segment was replaced.
func (r *agentRunDeadline) newSegment(interruptCause error) (context.Context, context.CancelCauseFunc, context.CancelFunc) {
	ctx, cancelSegment := context.WithCancelCause(r.Context)
	cancelWithCause := func(cause error) {
		if cause == nil || errors.Is(cause, context.Canceled) || errors.Is(cause, interruptCause) {
			// A late HITL/callback may report normal cancellation after this
			// segment was retired. It must not cancel its live sibling.
			cancelSegment(cause)
			return
		}
		r.cancel(cause)
	}
	return ctx, cancelWithCause, func() { cancelSegment(nil) }
}

func (r *agentRunDeadline) close() {
	mcp.CloseAgentRunBudget(r.Context)
	r.cancel(nil)
	r.timeoutCancel()
}

// agentRunContextError also checks the absolute deadline: its timer callback may
// not have run yet. A continuation must not start model/tool work in that gap.
func agentRunContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
