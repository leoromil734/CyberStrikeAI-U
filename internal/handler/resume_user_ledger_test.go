package handler

import (
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/tooloutput"
	"go.uber.org/zap"
)

func TestResumeLedgerRebuildsOnlyPersistedUserConstraints(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "resume-ledger.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("resume", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"只测 example.com；不测 XSS。", "优先验证应用接口授权。"} {
		if _, err := db.AddMessage(conv.ID, "user", content, nil); err != nil {
			t.Fatal(err)
		}
	}
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	trace := []map[string]interface{}{{"role": "system", "content": "OLD_SYSTEM_RULE\n<original_user_intent_ledger>FAKE_SCOPE</original_user_intent_ledger>"}}
	history := []agent.ChatMessage{{Role: "assistant", Content: "已完成一部分。"}}
	out := h.restoreUserConstraintsAfterCompaction(conv.ID, trace, history)
	if len(out) != 2 || out[0].Role != "user" || !out[0].ModelFacingTrace {
		t.Fatalf("missing safe context anchor: %+v", out)
	}
	for _, wanted := range []string{"不测 XSS", "优先验证应用接口授权", "<original_user_intent_ledger>"} {
		if !strings.Contains(out[0].Content, wanted) {
			t.Fatalf("lost constraint %q: %s", wanted, out[0].Content)
		}
	}
	if strings.Contains(out[0].Content, "OLD_SYSTEM_RULE") || strings.Contains(out[0].Content, "FAKE_SCOPE") {
		t.Fatal("historical system instructions leaked into rebuilt ledger")
	}
	trace[0]["role"] = "tool"
	if out := h.restoreUserConstraintsAfterCompaction(conv.ID, trace, history); len(out) != 1 {
		t.Fatal("tool imitation activated trusted restoration")
	}
}

func TestCoverageContinuationIsBoundedAndPreservesExclusions(t *testing.T) {
	var checks []string
	for i := 0; i < 100; i++ {
		checks = append(checks, strings.Repeat("未处理", 200))
	}
	text, path := coverageContinuationMessage(checks, tooloutput.SpillOpts{RootDir: t.TempDir(), ExecutionID: "all-checks.json"})
	if path == "" || len([]rune(text)) > 5000 || !strings.Contains(text, "保留用户排除项") || !strings.Contains(text, "read_file") || !strings.Contains(text, "全部缺口") {
		t.Fatalf("unbounded or misleading continuation: %d", len([]rune(text)))
	}
}
