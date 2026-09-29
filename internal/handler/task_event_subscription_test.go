package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
)

type cancelOnSSEFlush struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelOnSSEFlush) Flush() {
	w.ResponseRecorder.Flush()
	w.cancel()
}

func TestTaskEventSubscriptionFlushesImmediatelyAndDisconnectLeavesTaskRunning(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &cancelOnSSEFlush{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	c, _ := gin.CreateTestContext(w)
	c.Set(security.ContextSessionKey, security.Session{UserID: "admin", Scope: database.RBACScopeAll})
	c.Request = httptest.NewRequest("GET", "/api/agent-loop/task-events?conversationId=running", nil).WithContext(ctx)
	bus := NewTaskEventBus()
	tasks := &AgentTaskManager{tasks: map[string]*AgentTask{
		"running": {ConversationID: "running", Status: "running"},
	}}
	h := &AgentHandler{db: &database.DB{}, tasks: tasks, taskEventBus: bus}
	h.SubscribeAgentTaskEvents(c)
	if !w.Flushed || w.Code != 200 || w.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("subscription not established immediately: code=%d headers=%v", w.Code, w.Header())
	}
	if task := tasks.GetTask("running"); task == nil || task.Status != "running" {
		t.Fatal("closing display subscription stopped the backend task")
	}
	bus.mu.RLock()
	defer bus.mu.RUnlock()
	if len(bus.subs) != 0 {
		t.Fatal("disconnected subscription leaked")
	}
}
