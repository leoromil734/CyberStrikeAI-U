package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func targetHandlerTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "targets.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func targetHandlerRequest(h *AgentHandler, session *security.Session, method, path, body, target string, fn gin.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if session != nil {
		c.Set(security.ContextSessionKey, *session)
	}
	if target != "" {
		c.Params = gin.Params{{Key: "target", Value: target}}
	}
	fn(c)
	return w
}

func TestTargetHandlersPendingRegistrationUsesSessionScope(t *testing.T) {
	db := targetHandlerTestDB(t)
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	at := time.Now()
	for _, fixture := range []struct{ user, queue, message string }{
		{"u1", "q1", "visible.example.com"}, {"u2", "q2", "private.example.com"},
	} {
		if _, err := db.RecordTaskTargets(fixture.queue, "t", fixture.message, "", fixture.user, at); err != nil {
			t.Fatal(err)
		}
	}
	session := &security.Session{UserID: "u1", Scope: database.RBACScopeOwn}
	w := targetHandlerRequest(h, session, http.MethodPost, "/api/targets/check", `{"text":"visible.example.com private.example.com"}`, "", h.CheckRunTargets)
	if w.Code != http.StatusOK {
		t.Fatalf("check status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Hits       []database.TargetRun `json:"hits"`
		NewTargets []string             `json:"newTargets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Hits) != 1 || response.Hits[0].Target != "visible.example.com" || response.Hits[0].RunCount != 0 || response.Hits[0].SubmittedCount != 1 || response.Hits[0].LastQueueID != "q1" {
		t.Fatalf("pending registration missing/leaked: %+v", response)
	}
	if len(response.NewTargets) != 1 || response.NewTargets[0] != "private.example.com" {
		t.Fatalf("private target existence leaked: %+v", response)
	}
	w = targetHandlerRequest(h, session, http.MethodGet, "/api/targets", "", "", h.ListRunTargets)
	var page struct {
		Targets []database.TargetRun `json:"targets"`
		Total   int                  `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != http.StatusOK || page.Total != 1 || len(page.Targets) != 1 {
		t.Fatalf("list leaked totals: status=%d body=%s err=%v", w.Code, w.Body.String(), err)
	}
	w = targetHandlerRequest(h, session, http.MethodDelete, "/api/targets/private.example.com", "", "private.example.com", h.DeleteRunTarget)
	if w.Code != http.StatusOK {
		t.Fatalf("scoped delete status=%d body=%s", w.Code, w.Body.String())
	}
	if hits, err := db.CheckTargetRuns([]string{"private.example.com"}); err != nil || len(hits) != 1 {
		t.Fatalf("deleted another user's registration: %+v err=%v", hits, err)
	}
}

func TestTargetHandlersRejectMissingSession(t *testing.T) {
	h := &AgentHandler{}
	for _, entry := range []struct {
		method string
		fn     gin.HandlerFunc
	}{
		{http.MethodPost, h.CheckRunTargets}, {http.MethodGet, h.ListRunTargets},
		{http.MethodGet, h.ListRunTargetEvents}, {http.MethodDelete, h.DeleteRunTarget},
	} {
		w := targetHandlerRequest(h, nil, entry.method, "/api/targets", `{}`, "example.com", entry.fn)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("missing session accepted: status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestRecordRunTargetsUsesCurrentRawChatInputAndKeepsNewTargets(t *testing.T) {
	db := targetHandlerTestDB(t)
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	conv, err := db.CreateConversation("renamed-title.example.com", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	firstMessage := "对 original.example.com 进行测试，poc.py 输出 results.json"
	if _, err := db.AddMessage(conv.ID, "user", firstMessage, nil); err != nil {
		t.Fatal(err)
	}
	h.recordRunTargets(conv.ID, firstMessage)
	if _, err := db.AddMessage(conv.ID, "assistant", "assistant-noise.example.com", nil); err != nil {
		t.Fatal(err)
	}
	laterMessage := "另一个目标 later-message.example.com，同时复查 original.example.com"
	if _, err := db.AddMessage(conv.ID, "user", laterMessage, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		h.recordRunTargets(conv.ID, laterMessage)
	}
	// 历史补漏只取首次输入，但不得清除后来真实登记的目标。
	if _, err := db.BackfillTargetRunsFromConversations(); err != nil {
		t.Fatal(err)
	}
	hits, err := db.CheckTargetRuns([]string{"original.example.com", "later-message.example.com"})
	if err != nil || len(hits) != 2 {
		t.Fatalf("later explicit target was not recorded: %+v err=%v", hits, err)
	}
	for _, hit := range hits {
		if hit.RunCount != 1 || hit.LastConversationID != conv.ID {
			t.Fatalf("same target/conversation lost idempotency: %+v", hit)
		}
	}
	if noise, err := db.CheckTargetRuns([]string{"renamed-title.example.com", "template.example.com", "assistant-noise.example.com", "poc.py", "results.json"}); err != nil || len(noise) != 0 {
		t.Fatalf("runtime registration picked title/assistant/file noise: %+v err=%v", noise, err)
	}
}

func TestRecordRunTargetsBatchPrefersCompleteTaskMessage(t *testing.T) {
	db := targetHandlerTestDB(t)
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	if _, err := db.Exec(`INSERT INTO batch_task_queues (id, title, role, status, created_at) VALUES ('q', 'truncated.example.com', 'template.example.com', 'pending', ?)`, time.Now()); err != nil {
		t.Fatal(err)
	}
	for i, message := range []string{
		strings.Repeat("完整原始任务输入 ", 100) + " full-task.example.com",
		"python poc.py 输出 results.json",
	} {
		conv, err := db.CreateConversation("renamed-title.example.com", database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.AddMessage(conv.ID, "user", "role-expanded.example.com", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO batch_tasks (id, queue_id, message, conversation_id, status) VALUES (?, 'q', ?, ?, 'pending')`, []string{"t-domain", "t-files"}[i], message, conv.ID); err != nil {
			t.Fatal(err)
		}
		h.recordRunTargets(conv.ID, "role-expanded.example.com template.example.com")
	}
	hits, err := db.CheckTargetRuns([]string{"full-task.example.com", "truncated.example.com", "renamed-title.example.com", "role-expanded.example.com", "template.example.com"})
	if err != nil || len(hits) != 1 || hits[0].Target != "full-task.example.com" || hits[0].RunCount != 1 {
		t.Fatalf("batch registration did not use only the full task input: %+v err=%v", hits, err)
	}
}
