package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newBatchContinuationTest(t *testing.T) (*AgentHandler, *BatchTaskQueue, security.Session) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	cfg := &config.Config{AI: config.AIConfig{DefaultChannel: "default", Channels: map[string]config.AIChannelConfig{
		"default": {Model: "default-model"}, "task": {Model: "task-model"}, "latest": {Model: "latest-model"},
	}}}
	cfg.MultiAgent.Enabled = true
	cfg.Agent.WorkspaceRootDir = t.TempDir()
	h := &AgentHandler{db: db, config: cfg, logger: zap.NewNop(), tasks: NewAgentTaskManager(), batchTaskManager: NewBatchTaskManager(zap.NewNop())}
	h.batchTaskManager.SetDB(db)
	h.tasks.assessmentStarter = h.beginGovernedContinuation
	h.tasks.assessmentFinisher = h.finishGovernedContinuation
	queue, err := h.batchTaskManager.CreateBatchQueue("existing queue", "saved-role", "eino_single", "manual", "", "", nil, 1, 0,
		[]BatchTaskInput{{Message: "edited task text", AIChannelID: "task"}})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("original", database.ConversationCreateMeta{RoleName: queue.Role})
	if err != nil {
		t.Fatal(err)
	}
	for resource, id := range map[string]string{"batch_task": queue.ID, "conversation": conv.ID} {
		if err := db.SetResourceOwner(resource, id, user.ID); err != nil {
			t.Fatal(err)
		}
	}
	h.batchTaskManager.UpdateTaskStatusWithConversationID(queue.ID, queue.Tasks[0].ID, BatchTaskStatusFailed, "original result", "original error", conv.ID)
	h.batchTaskManager.UpdateQueueStatus(queue.ID, BatchQueueStatusCompleted)
	queue, _ = h.batchTaskManager.GetBatchQueue(queue.ID)
	session := security.Session{UserID: user.ID, Scope: database.RBACScopeOwn,
		Permissions: map[string]bool{"tasks:write": true, "tasks:read": true, "chat:write": true, "chat:read": true},
		PermissionScopes: map[string]string{"tasks:write": database.RBACScopeOwn, "tasks:read": database.RBACScopeOwn,
			"chat:write": database.RBACScopeOwn, "chat:read": database.RBACScopeOwn},
	}
	return h, queue, session
}

func batchContinuationRouter(h *AgentHandler, session security.Session) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(security.ContextSessionKey, session); c.Next() })
	r.Use(security.RBACMiddleware(h.db))
	r.POST("/api/batch-tasks/:queueId/tasks/:taskId/continue", h.ContinueBatchTask)
	r.GET("/api/batch-tasks/:queueId/tasks/:taskId/original-message", h.GetBatchTaskOriginalMessage)
	return r
}

func batchContinuationPath(q *BatchTaskQueue, suffix string) string {
	return "/api/batch-tasks/" + q.ID + "/tasks/" + q.Tasks[0].ID + "/" + suffix
}

func batchContinuationContext(q *BatchTaskQueue, s security.Session) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, batchContinuationPath(q, "continue"), nil)
	c.Set(security.ContextSessionKey, s)
	c.Params = gin.Params{{Key: "queueId", Value: q.ID}, {Key: "taskId", Value: q.Tasks[0].ID}}
	return c, w
}

func TestBatchTaskOriginalMessage(t *testing.T) {
	const original = "  最初输入\n目标：https://example.invalid:8443/path?q=1\n保留所有空白\n"
	for _, tc := range []struct {
		name, source, message string
		status                int
	}{
		{"conversation", "conversation", original, http.StatusOK},
		{"without-conversation", "task", "edited task text", http.StatusOK},
		{"no-user-message", "", "", http.StatusNotFound},
		{"database-error", "", "", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, q, s := newBatchContinuationTest(t)
			id := q.Tasks[0].ConversationID
			switch tc.name {
			case "conversation":
				for i, msg := range []struct{ role, text string }{{"system", "not a user"}, {"assistant", "not a user either"}, {"user", original}, {"assistant", "large result"}, {"user", "继续"}} {
					row, err := h.db.AddMessage(id, msg.role, msg.text, nil)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := h.db.Exec("UPDATE messages SET created_at = ? WHERE id = ?", time.Unix(100+int64(i), 0), row.ID); err != nil {
						t.Fatal(err)
					}
				}
			case "without-conversation":
				h.batchTaskManager.queues[q.ID].Tasks[0].ConversationID = ""
			case "database-error":
				if _, err := h.db.Exec("ALTER TABLE messages RENAME TO temporarily_unavailable_messages"); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			batchContinuationRouter(h, s).ServeHTTP(w, httptest.NewRequest(http.MethodGet, batchContinuationPath(q, "original-message"), nil))
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			var body map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if tc.status == http.StatusOK {
				if len(body) != 2 || body["message"] != tc.message || body["source"] != tc.source {
					t.Fatalf("inexact payload: %#v", body)
				}
			} else if _, ok := body["message"]; ok || strings.Contains(w.Body.String(), "edited task text") {
				t.Fatalf("silently fell back to edited task: %s", w.Body.String())
			}
		})
	}
}

func TestBatchTaskConversationActionPermissions(t *testing.T) {
	for _, action := range []struct{ method, suffix, tasks, chat string }{
		{http.MethodPost, "continue", "tasks:write", "chat:write"},
		{http.MethodGet, "original-message", "tasks:read", "chat:read"},
	} {
		for _, denial := range []string{"missing-tasks", "missing-chat", "foreign-queue", "foreign-conversation", "broad-tasks-narrow-chat", "broad-chat-narrow-tasks"} {
			t.Run(action.suffix+"/"+denial, func(t *testing.T) {
				h, q, s := newBatchContinuationTest(t)
				id := q.Tasks[0].ConversationID
				_, _ = h.db.AddMessage(id, "user", "secret original target", nil)
				switch denial {
				case "missing-tasks":
					delete(s.Permissions, action.tasks)
				case "missing-chat":
					delete(s.Permissions, action.chat)
				case "foreign-queue", "broad-chat-narrow-tasks":
					if _, err := h.db.Exec("UPDATE batch_task_queues SET owner_user_id = ? WHERE id = ?", "other", q.ID); err != nil {
						t.Fatal(err)
					}
					if denial == "broad-chat-narrow-tasks" {
						s.PermissionScopes[action.chat] = database.RBACScopeAll
					}
				case "foreign-conversation", "broad-tasks-narrow-chat":
					if _, err := h.db.Exec("UPDATE conversations SET owner_user_id = ? WHERE id = ?", "other", id); err != nil {
						t.Fatal(err)
					}
					if denial == "broad-tasks-narrow-chat" {
						s.PermissionScopes[action.tasks] = database.RBACScopeAll
					}
				}
				w := httptest.NewRecorder()
				batchContinuationRouter(h, s).ServeHTTP(w, httptest.NewRequest(action.method, batchContinuationPath(q, action.suffix), nil))
				if w.Code != http.StatusForbidden {
					t.Fatalf("permission bypass: %d %s", w.Code, w.Body.String())
				}
				if strings.Contains(w.Body.String(), id) || strings.Contains(w.Body.String(), "secret") {
					t.Fatalf("leaked conversation: %s", w.Body.String())
				}
				messages, err := h.db.GetMessages(id)
				if err != nil || len(messages) != 1 {
					t.Fatalf("denial mutated messages: %v, %v", messages, err)
				}
			})
		}
	}
}

func TestBatchTaskContinuationRejectsActiveOrMissingConversation(t *testing.T) {
	for _, tc := range []struct{ name, errorType string }{
		{"no-conversation", "missing_conversation"}, {"queue-running", "queue_active"}, {"executor-active", "queue_active"},
		{"task-running", "queue_active"}, {"conversation-running", "task_already_running"}, {"conversation-cancelling", "task_already_running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, q, s := newBatchContinuationTest(t)
			live := h.batchTaskManager.queues[q.ID]
			id := q.Tasks[0].ConversationID
			switch tc.name {
			case "no-conversation":
				live.Tasks[0].ConversationID = ""
			case "queue-running":
				live.Status = BatchQueueStatusRunning
			case "executor-active":
				live.Status = BatchQueueStatusPaused
				h.batchTaskManager.TryMarkQueueExecutor(q.ID)
			case "task-running":
				live.Tasks[0].Status = BatchTaskStatusRunning
			default:
				if _, err := h.tasks.StartTask(id, "existing run", nil); err != nil {
					t.Fatal(err)
				}
				if tc.name == "conversation-cancelling" {
					h.tasks.CancelTask(id, ErrTaskCancelled)
				}
			}
			before, _ := h.batchTaskManager.GetBatchQueue(q.ID)
			w := httptest.NewRecorder()
			batchContinuationRouter(h, s).ServeHTTP(w, httptest.NewRequest(http.MethodPost, batchContinuationPath(q, "continue"), nil))
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), tc.errorType) {
				t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
			}
			after, _ := h.batchTaskManager.GetBatchQueue(q.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("continuation changed historical queue/task")
			}
			messages, err := h.db.GetMessages(id)
			if err != nil || len(messages) != 0 {
				t.Fatalf("rejected continuation inserted messages: %v %v", messages, err)
			}
		})
	}
}

func TestBatchTaskContinuationAllowsStoppedStatesWithoutRewritingSnapshot(t *testing.T) {
	for _, status := range []string{BatchTaskStatusDeclined, BatchTaskStatusFailed, BatchTaskStatusBlocked, BatchTaskStatusPaused, BatchTaskStatusCancelled, BatchTaskStatusCompleted} {
		t.Run(status, func(t *testing.T) {
			h, q, s := newBatchContinuationTest(t)
			h.batchTaskManager.UpdateTaskStatus(q.ID, q.Tasks[0].ID, status, "saved evidence", "saved reason")
			before, _ := h.batchTaskManager.GetBatchQueue(q.ID)
			c, w := batchContinuationContext(q, s)
			if _, _, ok := h.prepareBatchTaskContinuation(c); !ok {
				t.Fatalf("stopped state rejected: %d %s", w.Code, w.Body.String())
			}
			after, _ := h.batchTaskManager.GetBatchQueue(q.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("preparation rewrote stopped task history")
			}
		})
	}
}

func TestBatchTaskContinuationPreservesRequest(t *testing.T) {
	for _, mode := range []string{"eino_single", "deep", "plan_execute", "supervisor"} {
		for _, assessment := range []string{database.AssessmentModeLegacy, database.AssessmentModeConversation, database.AssessmentModeExecution, database.AssessmentModeComprehensive} {
			t.Run(mode+"/"+assessment, func(t *testing.T) {
				h, q, s := newBatchContinuationTest(t)
				live := h.batchTaskManager.queues[q.ID]
				live.AgentMode, live.AssessmentMode = mode, assessment
				id := q.Tasks[0].ConversationID
				if err := h.db.SetConversationAIChannel(id, "latest", "latest-model"); err != nil {
					t.Fatal(err)
				}
				c, w := batchContinuationContext(q, s)
				req, gotMode, ok := h.prepareBatchTaskContinuation(c)
				if !ok {
					t.Fatalf("preparation failed: %d %s", w.Code, w.Body.String())
				}
				if req.Message != "继续" || req.ConversationID != id || req.Role != q.Role || req.AIChannelID != "latest" || gotMode != mode {
					t.Fatalf("lost request identity: %+v mode=%s", req, gotMode)
				}
				if mode != "eino_single" && req.Orchestration != mode {
					t.Fatalf("lost orchestration: %+v", req)
				}
				exec, coverage := assessmentModeRequirements(assessment)
				if req.Finalization.RequireExecutionEvidence == nil || *req.Finalization.RequireExecutionEvidence != exec || req.Finalization.RequireCoverageEvidence == nil || *req.Finalization.RequireCoverageEvidence != coverage {
					t.Fatalf("lost finalization policy: %+v", req.Finalization)
				}
			})
		}
	}
}

func TestBatchTaskContinuationRetainsStricterPreviousAssessmentAndChannelFallback(t *testing.T) {
	h, q, s := newBatchContinuationTest(t)
	project, err := h.db.CreateProject(&database.Project{Name: "original project"})
	if err != nil {
		t.Fatal(err)
	}
	id := q.Tasks[0].ConversationID
	if _, err := h.db.Exec("UPDATE conversations SET project_id = ? WHERE id = ?", project.ID, id); err != nil {
		t.Fatal(err)
	}
	previous, err := h.db.BeginAssessmentRun(id, project.ID, q.ID, q.Tasks[0].ID, database.AssessmentModeComprehensive, "original-assessment")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.FinishAssessmentRun(previous.ID, "blocked", "missing_coverage", "blocked"); err != nil {
		t.Fatal(err)
	}
	c, w := batchContinuationContext(q, s)
	req, _, ok := h.prepareBatchTaskContinuation(c)
	if !ok {
		t.Fatal(w.Body.String())
	}
	if req.AIChannelID != "task" || req.ProjectID != project.ID || !*req.Finalization.RequireExecutionEvidence || !*req.Finalization.RequireCoverageEvidence {
		t.Fatalf("lost existing policy/project/fallback channel: %+v", req)
	}
	if _, err := h.tasks.StartTask(id, req.Message, nil); err != nil {
		t.Fatal(err)
	}
	run, err := h.db.LatestAssessmentRun(id)
	if err != nil || run.ID == previous.ID || run.AssessmentID != previous.AssessmentID || run.QueueID != q.ID || run.TaskID != q.Tasks[0].ID {
		t.Fatalf("assessment not continued: %+v %v", run, err)
	}
	h.tasks.FinishTask(id, "failed")
	after, _ := h.batchTaskManager.GetBatchQueue(q.ID)
	if !reflect.DeepEqual(q, after) {
		t.Fatal("assessment continuation rewrote batch history")
	}
}

func TestBatchTaskContinuationFailsClosedOnConfigurationErrors(t *testing.T) {
	for _, name := range []string{"missing-conversation", "missing-channel", "changed-model", "metadata-db-error", "assessment-db-error", "multi-agent-disabled"} {
		t.Run(name, func(t *testing.T) {
			h, q, s := newBatchContinuationTest(t)
			s.Scope = database.RBACScopeAll
			for k := range s.PermissionScopes {
				s.PermissionScopes[k] = database.RBACScopeAll
			}
			id := q.Tasks[0].ConversationID
			want := http.StatusInternalServerError
			switch name {
			case "missing-conversation":
				_, _ = h.db.Exec("DELETE FROM conversations WHERE id = ?", id)
				want = http.StatusNotFound
			case "missing-channel":
				_ = h.db.SetConversationAIChannel(id, "deleted", "original-model")
				want = http.StatusBadRequest
			case "changed-model":
				_ = h.db.SetConversationAIChannel(id, "task", "different-original-model")
				want = http.StatusConflict
			case "metadata-db-error":
				_, _ = h.db.Exec("DROP TABLE conversation_ai_channels")
			case "assessment-db-error":
				_, _ = h.db.Exec("DROP TABLE assessment_runs")
			case "multi-agent-disabled":
				h.batchTaskManager.queues[q.ID].AgentMode = "deep"
				h.config.MultiAgent.Enabled = false
				want = http.StatusBadRequest
			}
			c, w := batchContinuationContext(q, s)
			if _, _, ok := h.prepareBatchTaskContinuation(c); ok || w.Code != want {
				t.Fatalf("configuration error ignored: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestPrepareMultiAgentSessionRejectsActiveBeforeWriting(t *testing.T) {
	h, q, s := newBatchContinuationTest(t)
	id := q.Tasks[0].ConversationID
	if _, err := h.tasks.StartTask(id, "existing", nil); err != nil {
		t.Fatal(err)
	}
	c, _ := batchContinuationContext(q, s)
	_, err := h.prepareMultiAgentSession(&ChatRequest{ConversationID: id, Message: "继续", Role: "new-role"}, c, "test")
	if !errors.Is(err, ErrTaskAlreadyRunning) {
		t.Fatalf("active task not rejected: %v", err)
	}
	meta, err := h.db.GetConversationContinuationMetadata(id)
	if err != nil || meta.RoleName != q.Role {
		t.Fatalf("active role mutated: %+v %v", meta, err)
	}
	messages, err := h.db.GetMessages(id)
	if err != nil || len(messages) != 0 {
		t.Fatalf("active conversation mutated: %+v %v", messages, err)
	}
}

// The callback observes real SSE frames while the handler still owns its task.
// No model is called: nil Agent (or a missing workflow) fails after registration.
type taskStartRecorder struct {
	*httptest.ResponseRecorder
	onEvent func(StreamEvent)
}

func (w *taskStartRecorder) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	for _, frame := range strings.Split(string(p), "\n\n") {
		if !strings.HasPrefix(frame, "data: ") {
			continue
		}
		var event StreamEvent
		if json.Unmarshal([]byte(strings.TrimPrefix(frame, "data: ")), &event) == nil && w.onEvent != nil {
			w.onEvent(event)
		}
	}
	return n, err
}

func TestBatchTaskContinuationSSEStartedContract(t *testing.T) {
	for _, mode := range []string{"eino_single", "deep", "workflow"} {
		for _, scenario := range []string{"started", "registration-failed", "racing-run"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				h, q, s := newBatchContinuationTest(t)
				id := q.Tasks[0].ConversationID
				if _, err := h.db.AddMessage(id, "user", "original https://example.invalid/a", nil); err != nil {
					t.Fatal(err)
				}
				if mode == "workflow" {
					h.config.Roles = map[string]config.RoleConfig{q.Role: {Enabled: true, WorkflowID: "absent-test-workflow"}}
				} else {
					h.batchTaskManager.queues[q.ID].AgentMode = mode
				}
				if scenario == "registration-failed" {
					h.tasks.assessmentStarter = func(string) (string, error) { return "", errors.New("test registration failure") }
				}
				before, _ := h.batchTaskManager.GetBatchQueue(q.ID)
				beforeDB, _ := h.db.GetBatchTasks(q.ID)
				startCount, errorCount, savedCount := 0, 0, 0
				w := &taskStartRecorder{ResponseRecorder: httptest.NewRecorder()}
				w.onEvent = func(event StreamEvent) {
					switch event.Type {
					case "message_saved":
						savedCount++
						if scenario == "racing-run" {
							if _, err := h.tasks.StartTask(id, "other request won", nil); err != nil {
								t.Fatal(err)
							}
						}
					case "task_started":
						startCount++
						active := h.tasks.GetTaskSnapshot(id)
						data, _ := event.Data.(map[string]interface{})
						if active == nil || active.Message != "继续" || data["conversationId"] != id || savedCount != 1 {
							t.Fatalf("premature/inexact start acknowledgement: %+v active=%+v", event, active)
						}
					case "error":
						errorCount++
					case "conversation":
						t.Fatal("continuation created a replacement conversation")
					}
				}
				// Untrusted body fields cannot change the literal message, model or role.
				request := httptest.NewRequest(http.MethodPost, batchContinuationPath(q, "continue"), strings.NewReader(`{"message":"override","role":"bad","conversationId":"other","aiChannelId":"deleted","finalization":{"requireExecutionEvidence":false}}`))
				batchContinuationRouter(h, s).ServeHTTP(w, request)
				wantStarts := 0
				if scenario == "started" {
					wantStarts = 1
				}
				if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") || startCount != wantStarts || errorCount == 0 {
					t.Fatalf("SSE contract failed: starts=%d errors=%d status=%d body=%s", startCount, errorCount, w.Code, w.Body.String())
				}
				if scenario == "racing-run" {
					if active := h.tasks.GetTaskSnapshot(id); active == nil || active.Message != "other request won" {
						t.Fatal("losing request removed or replaced the winning task")
					}
				}
				after, _ := h.batchTaskManager.GetBatchQueue(q.ID)
				afterDB, _ := h.db.GetBatchTasks(q.ID)
				if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeDB, afterDB) {
					t.Fatal("continuation reset historical task snapshot")
				}
				messages, err := h.db.GetMessages(id)
				if err != nil || len(messages) != 3 || messages[0].Content != "original https://example.invalid/a" {
					t.Fatalf("history changed: %+v %v", messages, err)
				}
				users := []string{}
				for _, msg := range messages {
					if msg.Role == "user" {
						users = append(users, msg.Content)
					}
				}
				if !reflect.DeepEqual(users, []string{"original https://example.invalid/a", "继续"}) {
					t.Fatalf("literal continuation altered: %q", users)
				}
			})
		}
	}
}

func TestBatchTaskContinuationSSEDisconnectDoesNotCancelRegisteredTask(t *testing.T) {
	h, q, s := newBatchContinuationTest(t)
	id := q.Tasks[0].ConversationID
	ctx, disconnect := context.WithCancel(context.Background())
	defer disconnect()
	started := false
	w := &taskStartRecorder{ResponseRecorder: httptest.NewRecorder()}
	w.onEvent = func(event StreamEvent) {
		if event.Type == "task_started" {
			started = true
			disconnect()
			if active := h.tasks.GetTaskSnapshot(id); active == nil || active.Status != "running" {
				t.Fatal("disconnect lost registered task")
			}
		}
	}
	batchContinuationRouter(h, s).ServeHTTP(w, httptest.NewRequest(http.MethodPost, batchContinuationPath(q, "continue"), nil).WithContext(ctx))
	completed := h.tasks.GetCompletedTasks()
	if !started || len(completed) != 1 || completed[0].Status != "failed" {
		t.Fatalf("detached run did not reach its own runner error: started=%v completed=%+v", started, completed)
	}
	var runnerErrors int
	err := h.db.QueryRow("SELECT COUNT(*) FROM process_details WHERE conversation_id = ? AND event_type = 'error' AND message LIKE ?", id, "%配置或 Agent 为空%").Scan(&runnerErrors)
	if err != nil || runnerErrors != 1 {
		t.Fatalf("disconnect prevented backend execution: runner errors=%d, err=%v", runnerErrors, err)
	}
}
