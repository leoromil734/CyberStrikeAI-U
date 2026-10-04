package handler

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/workspaceguard"
)

func requireRunDeadline(t *testing.T, ctx context.Context, want time.Time) {
	t.Helper()
	got, ok := ctx.Deadline()
	if !ok || !got.Equal(want) {
		t.Fatalf("deadline = %v, present=%v; want exactly %v", got, ok, want)
	}
}

func TestAgentRunDeadlineRetainsValuesAndIgnoresSSEDisconnect(t *testing.T) {
	type projectKey struct{}
	requestCtx, disconnect := context.WithCancel(context.Background())
	requestCtx = authctx.WithPrincipal(requestCtx, authctx.NewPrincipal("owner", "user", "assigned", map[string]bool{"agent:execute": true}))
	requestCtx = context.WithValue(requestCtx, projectKey{}, "project-1")
	policy := &workspaceguard.Policy{Workspace: "workspace-1", EvidenceRoot: "evidence-1"}
	requestCtx = workspaceguard.WithPolicy(requestCtx, policy)
	deadline := time.Now().Add(time.Minute)
	run := newAgentRunDeadline(detachedAgentContext(requestCtx), deadline)
	defer run.close()
	disconnect()
	requireRunDeadline(t, run, deadline)
	if err := agentRunContextError(run); err != nil {
		t.Fatalf("SSE disconnect cancelled the run: %v", err)
	}
	principal, ok := authctx.PrincipalFromContext(run)
	if !ok || principal.UserID != "owner" || !principal.HasPermission("agent:execute") || run.Value(projectKey{}) != "project-1" || workspaceguard.FromContext(run) != policy {
		t.Fatal("request authorization/project/workspace values were lost")
	}
}

func TestAgentRunDeadlineSegmentIsolationAndTerminalStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		interrupt := errors.New("interrupt this segment")
		userStop := errors.New("stop this request")
		deadline := time.Now().Add(5 * time.Second)
		run := newAgentRunDeadline(context.Background(), deadline)
		defer run.close()
		segment, cancel, cleanup := run.newSegment(interrupt)
		defer func() { cleanup() }()
		for range 6 {
			oldSegment, oldCancel, oldCleanup := segment, cancel, cleanup
			cancel(interrupt)
			if !errors.Is(context.Cause(oldSegment), interrupt) || run.Err() != nil {
				t.Fatal("interrupt escaped the segment")
			}
			segment, cancel, cleanup = run.newSegment(interrupt)
			oldCleanup()
			oldCancel(nil)
			oldCancel(context.Canceled)
			oldCancel(interrupt)
			requireRunDeadline(t, segment, deadline)
			if segment.Err() != nil {
				t.Fatal("old segment cleanup/callback cancelled the replacement")
			}
		}
		oldCancel := cancel
		cleanup()
		segment, cancel, cleanup = run.newSegment(interrupt)
		oldCancel(userStop)
		if !errors.Is(context.Cause(run), userStop) || !errors.Is(context.Cause(segment), userStop) {
			t.Fatal("terminal stop captured before rebind was lost")
		}
		cleanup()
		segment, cancel, cleanup = run.newSegment(interrupt)
		requireRunDeadline(t, segment, deadline)
		if !errors.Is(context.Cause(segment), userStop) {
			t.Fatal("terminally cancelled request was revived")
		}
	})
}

func TestAgentRunDeadlineExpiryAndNewRequestBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requestCtx := context.Background()
		deadline := time.Now().Add(5 * time.Second)
		run := newAgentRunDeadline(requestCtx, deadline)
		defer run.close()
		segment, _, cancelSegment := run.newSegment(errors.New("interrupt"))
		defer cancelSegment()
		requireRunDeadline(t, segment, deadline)
		// Virtual time advances to the fixed deadline; no sleep or real wait.
		<-run.Done()
		if !errors.Is(agentRunContextError(run), context.DeadlineExceeded) || !errors.Is(segment.Err(), context.DeadlineExceeded) {
			t.Fatalf("deadline failed to cancel run/segment: %v / %v", run.Err(), segment.Err())
		}
		expired, _, cancelExpired := run.newSegment(errors.New("interrupt"))
		defer cancelExpired()
		requireRunDeadline(t, expired, deadline)
		if !errors.Is(agentRunContextError(expired), context.DeadlineExceeded) {
			t.Fatal("new segment reset the expired request deadline")
		}
		newDeadline := time.Now().Add(5 * time.Second)
		newRequest := newAgentRunDeadline(requestCtx, newDeadline)
		defer newRequest.close()
		requireRunDeadline(t, newRequest, newDeadline)
		if newRequest.Err() != nil || !newDeadline.After(deadline) {
			t.Fatal("an explicit new request inherited the previous exhausted budget")
		}
	})
}

func TestAgentRunDeadlinePreservesNonStreamCancellationAndEarlierDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	parent, cancelParent := context.WithDeadline(context.Background(), deadline)
	defer cancelParent()
	run := newAgentRunDeadline(parent, deadline.Add(time.Hour))
	defer run.close()
	requireRunDeadline(t, run, deadline)
	cancelParent()
	if !errors.Is(agentRunContextError(run), context.Canceled) {
		t.Fatal("non-streaming request cancellation was detached")
	}
}

// Models a timer callback that has not yet executed even though wall time has
// reached its deadline, so Err alone would incorrectly admit one more Run.
type delayedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestAgentRunDeadlineRejectsExpiredContextBeforeTimerCallback(t *testing.T) {
	ctx := delayedDeadlineContext{Context: context.Background(), deadline: time.Unix(1, 0)}
	if ctx.Err() != nil || !errors.Is(agentRunContextError(ctx), context.DeadlineExceeded) {
		t.Fatal("expired absolute deadline allowed another segment before timer callback")
	}
	run := newAgentRunDeadline(context.Background(), time.Unix(1, 0))
	defer run.close()
	if !errors.Is(run.Err(), context.DeadlineExceeded) {
		t.Fatal("an expired deadline was given a fresh budget")
	}
}
