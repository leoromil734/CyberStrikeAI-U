package handler

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func TestSubmittedReportRequestsContinuationUntilChecksPass(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "report-resume.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("report resume", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, logger: zap.NewNop(), config: &config.Config{MultiAgent: config.MultiAgentConfig{EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{ReductionRootDir: t.TempDir()}}}}
	report := "# 评估报告\n## 风险概览与测试范围\n" + strings.Repeat("授权范围和测试概览。", 40) + "\n## 已确认发现与范围限制\n未完成的发现验证和覆盖限制。"
	for _, submitted := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		result := &multiagent.RunResult{ReportSubmitted: submitted, SubmittedReport: report, Response: report, LastAgentTraceInput: `[{"role":"user","content":"scope must survive"},{"role":"assistant","content":"draft"}]`}
		d := coverageDecision(10, "unverified endpoint")
		d.FinalText, d.CoverageRepairBlocked, d.CoverageUnresolvedGroups = report, true, 20000
		state := &finalizationContinuationState{}
		var history []agent.ChatMessage
		message := "scope must survive"
		h.tryAutoContinueAfterFinalization(ctx, conv.ID, result, d, state, &history, &message, func(kind, _ string, _ interface{}) {
			if kind == "finalization_auto_continue" {
				cancel()
			}
		})
		cancel()
		if state.Attempts != 1 || state.WorkMode != "classify_and_verify" || len(history) == 0 || history[0].Content != "scope must survive" {
			t.Fatalf("report bypassed continuation: submitted=%v state=%+v", submitted, state)
		}
		if !strings.Contains(message, "停止逐条抄写事实不等于停止实际测试") || !strings.Contains(message, "20000") || result.SubmittedReport != report {
			t.Fatalf("lost classification instructions or candidate: %s", message)
		}
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
