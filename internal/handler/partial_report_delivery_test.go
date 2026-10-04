package handler

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func TestSubmittedOrCompleteCandidateStopsCoverageContinuation(t *testing.T) {
	report := "# 评估报告\n## 风险概览与测试范围\n" + strings.Repeat("授权范围和测试概览。", 40) + "\n## 已确认发现与范围限制\n未完成的发现验证和覆盖限制。"
	for _, tt := range []struct {
		name   string
		result *multiagent.RunResult
		text   string
		want   bool
	}{
		{"root exit", &multiagent.RunResult{ReportSubmitted: true, SubmittedReport: report}, report, true},
		{"ordinary report", &multiagent.RunResult{Response: report}, report, true},
		{"short bookkeeping", &multiagent.RunResult{Response: "计数已经对齐。"}, "计数已经对齐。", false},
		{"missing result", nil, report, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := agentfinalizer.Decision{Status: "in_progress", CompletionReason: agentfinalizer.ReasonCoverageIncomplete, FinalText: tt.text}
			if got := reportEndsFinalizationContinuation(tt.result, d); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
			if !tt.want {
				return
			}
			h := &AgentHandler{}
			state := &finalizationContinuationState{}
			var history []agent.ChatMessage
			message := "original user scope"
			if h.tryAutoContinueAfterFinalization(context.Background(), "offline", tt.result, d, state, &history, &message, nil) {
				t.Fatal("restarted model after report")
			}
			if state.Attempts != 0 || message != "original user scope" || !strings.Contains(state.StopReason, "不再自动补写") {
				t.Fatalf("unexpected continuation state: %+v", state)
			}
			stopped := finalizationStoppedDecision(d, state)
			if stopped.Status != "blocked" || stopped.Finalizable || stopped.Finalized {
				t.Fatalf("report upgraded assessment: %+v", stopped)
			}
		})
	}
}

func TestSubmittedExitCannotTriggerEmptyResponseRetry(t *testing.T) {
	h := &AgentHandler{}
	var history []agent.ChatMessage
	message, attempt := "original scope", 0
	result := &multiagent.RunResult{ReportSubmitted: true, LastAgentTraceInput: `[{"role":"user","content":"current"}]`}
	if h.tryContinueOnEinoEmptyResponse(context.Background(), nil, "offline", result, &attempt, &history, &message, true, nil) || attempt != 0 || message != "original scope" {
		t.Fatal("exit restarted through empty-response retry")
	}
}

func TestPersistPartialDeliveryMatchesSSEAndRetainsOriginal(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "delivery.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("offline", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := db.AddMessage(conv.ID, "assistant", "stale message", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	original := "unverified candidate, not delivered"
	d := h.persistFinalizationDecision(conv.ID, msg.ID, "eino_deep", nil, "reasoning preserved", agentfinalizer.Decision{
		Status: "blocked", CompletionReason: agentfinalizer.ReasonCoverageIncomplete, FinalText: original, MissingChecks: []string{"all original checks"},
	})
	if !d.DeliveryAvailable || d.Status != "blocked" || d.Finalizable {
		t.Fatalf("partial missing or promoted: %+v", d)
	}
	var content, reasoning string
	if err := db.QueryRow("SELECT content, reasoning_content FROM messages WHERE id = ?", msg.ID).Scan(&content, &reasoning); err != nil {
		t.Fatal(err)
	}
	if content != d.DeliveryText || content != finalizationBlockedMessage(d) || reasoning != "reasoning preserved" {
		t.Fatal("database and SSE diverged")
	}
	if finalizationResponsePayload(d, nil)["deliveryText"] != content {
		t.Fatal("SSE lost prepared delivery")
	}
	details, err := db.GetProcessDetails(msg.ID)
	if err != nil || len(details) != 1 {
		t.Fatalf("original diagnostic missing: %v %+v", err, details)
	}
	encoded, err := json.Marshal(details)
	if err != nil || !strings.Contains(string(encoded), original) || !strings.Contains(string(encoded), "all original checks") {
		t.Fatal("original candidate/checks discarded")
	}
	batch := batchSubTaskDeliveryDecision(&multiagent.RunResult{}, d)
	payload := batchSubTaskDoneEvent(conv.ID, "blocked", batch).Data.(map[string]interface{})
	if payload["status"] != "blocked" || payload["finalized"] != false || payload["deliveryText"] != content {
		t.Fatal("batch done lost true state/report")
	}
}
