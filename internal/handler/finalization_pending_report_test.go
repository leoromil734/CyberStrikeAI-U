package handler

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func TestSubmittedExitWaitsForPendingToolsBeforeContinuationBudget(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "wait.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("pending exit", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	execution := &mcp.ToolExecution{ID: "pending-katana", ConversationID: conv.ID, ToolName: "katana", Status: "running", StartTime: time.Now()}
	if err := db.SaveToolExecution(execution); err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	state := &finalizationContinuationState{Attempts: finalizationCoverageMaxAttempts, WorkAttempts: finalizationCoverageMaxAttempts}
	d := agentfinalizer.Decision{Status: "in_progress", CompletionReason: agentfinalizer.ReasonPendingTools, PendingExecutionIDs: []string{execution.ID}, FinalText: "已提交的报告。"}
	result := &multiagent.RunResult{ReportSubmitted: true, SubmittedReport: d.FinalText}
	var history []agent.ChatMessage
	message, waited := "scope", false
	ok := h.tryAutoContinueAfterFinalization(context.Background(), conv.ID, result, d, state, &history, &message, func(kind, _ string, _ interface{}) {
		if kind == "finalization_waiting_tools" {
			waited = true
			end := time.Now()
			execution.Status, execution.EndTime = "completed", &end
			if err := db.SaveToolExecution(execution); err != nil {
				t.Fatal(err)
			}
		}
	})
	if ok || !waited || !strings.Contains(state.StopReason, "安全上限") || state.Attempts != finalizationCoverageMaxAttempts {
		t.Fatalf("exit bypassed pending work/budget: ok=%v waited=%v state=%+v", ok, waited, state)
	}
	got, err := db.GetToolExecution(execution.ID)
	if err != nil || got.Status != "completed" {
		t.Fatalf("tool was cancelled instead of awaited: %+v %v", got, err)
	}
}

func TestFinalizationWaitUsesRequestDeadlineAndFailsClosed(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if got := finalizationToolWaitDeadline(ctx); !got.Equal(deadline) {
		t.Fatal("long tool wait was shortened")
	}
	h := &AgentHandler{}
	if err := h.waitFinalizationPendingExecutions(ctx, "conv", []string{"id"}); err == nil {
		t.Fatal("unknown tool state treated as completed")
	}
	cancel()
	if err := h.waitFinalizationPendingExecutions(ctx, "conv", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}

func TestReportCandidateSurvivesLaterBookkeepingWithoutPromotion(t *testing.T) {
	state := &finalizationContinuationState{LastReportCandidate: "original report", StopReason: "budget stopped"}
	d := finalizationStoppedDecision(coverageDecision(10, "original gap"), state)
	d.FinalText = "latest work notice"
	payload := agentfinalizer.ResponsePayload(d, nil)
	if payload["candidateReport"] != "original report" || d.FinalText != "latest work notice" || d.Finalizable || d.Finalized {
		t.Fatalf("candidate lost or promoted: %+v", d)
	}
}

func TestMissingOrUnsubmittedReportCanContinue(t *testing.T) {
	for _, reason := range []string{agentfinalizer.ReasonEmptyResponse, agentfinalizer.ReasonReportNotSubmitted} {
		d := agentfinalizer.Decision{Status: "blocked", CompletionReason: reason}
		if !shouldAutoContinueAfterFinalization(d, 0) || shouldAutoContinueAfterFinalization(d, finalizationAutoContinueMaxAttempts) {
			t.Fatalf("report repair is absent or unbounded: %s", reason)
		}
		if !strings.Contains(finalizationResumeInstruction(d), "exit 仅表示请求收尾") {
			t.Fatal("missing explicit report repair instruction")
		}
	}
}

func TestRuntimeFailureWithoutDatabaseStillReturnsReport(t *testing.T) {
	h := &AgentHandler{}
	for _, err := range []error{errors.New("provider unavailable"), context.DeadlineExceeded, context.Canceled} {
		d := h.persistRuntimeFailureForDelivery(context.Background(), "conv", "", "eino_deep", nil, nil, err)
		if !d.DeliveryAvailable || !d.RunTerminated || !strings.Contains(d.DeliveryText, "阶段报告") || d.Finalized || d.Finalizable {
			t.Fatalf("runtime failure ended without incomplete report: %+v", d)
		}
	}
}
