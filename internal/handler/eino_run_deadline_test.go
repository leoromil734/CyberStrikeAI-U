package handler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/workspaceguard"

	"go.uber.org/zap"
)

func deadlineTestHandler() *AgentHandler {
	// Avoid the unrelated task-manager cleanup ticker in virtual-time tests.
	return &AgentHandler{tasks: &AgentTaskManager{tasks: make(map[string]*AgentTask)}}
}

func TestEinoRunDeadlineRebindPreservesBudgetValuesAndSegmentIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := deadlineTestHandler()
		parent := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("owner", "user", "assigned", nil))
		parent = mcp.WithMCPProjectID(parent, "project-1")
		policy := &workspaceguard.Policy{Workspace: "workspace-1"}
		parent = workspaceguard.WithPolicy(parent, policy)
		deadline := time.Now().Add(5 * time.Second)
		run := newAgentRunDeadline(parent, deadline)
		defer run.close()
		base, cancel, task, cleanup := run.newEinoSegment()
		defer func() { cleanup() }()
		if _, err := h.tasks.StartTask("conv", "explicit request", cancel); err != nil {
			t.Fatal(err)
		}
		for _, continuation := range []string{"finalization", "empty_response", "interrupt_continue", "finalization", "empty_response"} {
			oldTask, oldCleanup, oldCancel := task, cleanup, cancel
			if continuation == "interrupt_continue" {
				if ok, err := h.tasks.CancelTask("conv", multiagent.ErrInterruptContinue); !ok || err != nil {
					t.Fatalf("interrupt: %v %v", ok, err)
				}
				if !errors.Is(context.Cause(base), multiagent.ErrInterruptContinue) || run.Err() != nil {
					t.Fatal("interrupt must cancel only the segment")
				}
			}
			base, cancel, task, cleanup = h.rebindEinoRunningTask(run, "conv", cleanup)
			oldCleanup()
			oldCancel(multiagent.ErrInterruptContinue)
			oldCancel(context.Canceled)
			oldCancel(nil)
			requireRunDeadline(t, task, deadline)
			if task.Err() != nil || oldTask.Err() == nil {
				t.Fatalf("%s: old segment cleanup leaked into new segment: %v / %v", continuation, oldTask.Err(), task.Err())
			}
			principal, ok := authctx.PrincipalFromContext(task)
			if !ok || principal.UserID != "owner" || mcp.MCPProjectIDFromContext(task) != "project-1" || workspaceguard.FromContext(task) != policy {
				t.Fatalf("%s: principal/project/workspace values lost", continuation)
			}
		}
		<-run.Done()
		if !errors.Is(task.Err(), context.DeadlineExceeded) {
			t.Fatalf("last segment outlived original deadline: %v", task.Err())
		}
		h.tasks.UpdateTaskStatus("conv", "timeout")
		_, _, expired, stopExpired := h.rebindEinoRunningTask(run, "conv", cleanup)
		defer stopExpired()
		requireRunDeadline(t, expired, deadline)
		if !errors.Is(agentRunContextError(expired), context.DeadlineExceeded) || h.tasks.GetTaskSnapshot("conv").Status != "timeout" {
			t.Fatal("expired continuation was revived as running")
		}
	})
}

func TestEinoRunDeadlineTerminalCancellationSurvivesRebind(t *testing.T) {
	for _, cancelOld := range []bool{false, true} {
		h := deadlineTestHandler()
		run := newAgentRunDeadline(context.Background(), time.Now().Add(time.Minute))
		_, oldCancel, _, cleanup := run.newEinoSegment()
		if _, err := h.tasks.StartTask("conv", "request", oldCancel); err != nil {
			t.Fatal(err)
		}
		_, _, task, cleanupNext := h.rebindEinoRunningTask(run, "conv", cleanup)
		if cancelOld {
			// A stop that captured the old callback before rebind still stops
			// the entire request, unlike the old segment's cleanup/interrupt.
			oldCancel(ErrTaskCancelled)
		} else if ok, err := h.tasks.CancelTask("conv", ErrTaskCancelled); !ok || err != nil {
			t.Fatalf("stop: %v %v", ok, err)
		}
		if !errors.Is(context.Cause(task), ErrTaskCancelled) || !errors.Is(context.Cause(run), ErrTaskCancelled) {
			t.Fatal("terminal stop was lost when rebinding")
		}
		_, _, stopped, stopStopped := h.rebindEinoRunningTask(run, "conv", cleanupNext)
		if !errors.Is(context.Cause(stopped), ErrTaskCancelled) {
			t.Fatal("user-cancelled request received a fresh segment")
		}
		stopStopped()
		run.close()
	}
}

func TestEinoRunDeadlineHITLApprovalAndWaitUseOriginalDeadline(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "deadline-hitl.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("deadline HITL", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h := deadlineTestHandler()
	h.db, h.logger = db, zap.NewNop()
	h.hitlManager = NewHITLManager(db, h.logger)
	if err := h.hitlManager.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
	h.hitlManager.ActivateConversation(conv.ID, &HITLRequest{Enabled: true, Mode: "approval", Reviewer: "human"})
	defer h.hitlManager.DeactivateConversation(conv.ID)
	synctest.Test(t, func(t *testing.T) {
		deadline := time.Now().Add(5 * time.Second)
		run := newAgentRunDeadline(context.Background(), deadline)
		defer run.close()
		_, cancel, task, cleanup := run.newEinoSegment()
		defer func() { cleanup() }()
		if _, err := h.tasks.StartTask(conv.ID, "request", cancel); err != nil {
			t.Fatal(err)
		}
		_, err := h.interceptHITLForEinoTool(task, cancel, conv.ID, "", func(kind, _ string, data interface{}) {
			if kind == "hitl_interrupt" {
				id := data.(map[string]interface{})["interruptId"].(string)
				if err := h.hitlManager.ResolveInterrupt(id, "approve", "", nil); err != nil {
					t.Fatal(err)
				}
			}
		}, "test-tool", "{}")
		if err != nil {
			t.Fatalf("HITL approval failed: %v", err)
		}
		requireRunDeadline(t, task, deadline)
		_, cancel, task, cleanup = h.rebindEinoRunningTask(run, conv.ID, cleanup)
		_, err = h.interceptHITLForEinoTool(task, cancel, conv.ID, "", func(kind, _ string, _ interface{}) {
			if kind == "hitl_interrupt" {
				<-run.Done() // Expire the original budget while awaiting approval.
			}
		}, "test-tool", "{}")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("HITL wait outlived run budget: %v", err)
		}
		_, _, task, cleanup = h.rebindEinoRunningTask(run, conv.ID, cleanup)
		requireRunDeadline(t, task, deadline)
		if !errors.Is(agentRunContextError(task), context.DeadlineExceeded) {
			t.Fatal("HITL timeout was followed by a fresh budget")
		}
	})
}
