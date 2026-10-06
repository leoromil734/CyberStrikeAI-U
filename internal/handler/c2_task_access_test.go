package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/c2"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestC2TaskWaitAndCancelRejectForeignTask(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "access.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateC2Listener(&database.C2Listener{ID: "l_foreign", Name: "test", Type: "http_beacon", BindHost: "127.0.0.1", BindPort: 12345, Status: "stopped", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("c2_listener", "l_foreign", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertC2Session(&database.C2Session{ID: "s_foreign", ListenerID: "l_foreign", ImplantUUID: "test-uuid", Status: "active", FirstSeenAt: time.Now(), LastCheckIn: time.Now()}); err != nil {
		t.Fatal(err)
	}
	task := &database.C2Task{ID: "t_foreign", SessionID: "s_foreign", TaskType: "exec", Status: "queued", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	h := NewC2Handler(c2.NewManager(db, zap.NewNop(), t.TempDir()), zap.NewNop())
	// Direct registration intentionally omits normal route RBAC. This verifies
	// defense in depth in the handlers, not a bypass of the existing RBAC routes.
	for _, authenticated := range []bool{false, true} {
		r := gin.New()
		if authenticated {
			r.Use(func(c *gin.Context) {
				c.Set(security.ContextSessionKey, security.Session{UserID: "other", Scope: database.RBACScopeOwn})
			})
		}
		r.GET("/tasks/:id/wait", h.WaitTask)
		r.POST("/tasks/:id/cancel", h.CancelTask)
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "/tasks/t_foreign/wait", nil),
			httptest.NewRequest(http.MethodPost, "/tasks/t_foreign/cancel", nil),
		} {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s: status=%d", req.URL, w.Code)
			}
		}
	}
	saved, err := db.GetC2Task(task.ID)
	if err != nil || saved == nil || saved.Status != "queued" {
		t.Fatal("foreign task mutated")
	}
	owned := gin.New()
	owned.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "owner", Scope: database.RBACScopeOwn})
	})
	owned.GET("/tasks/:id/wait", h.WaitTask)
	owned.POST("/tasks/:id/cancel", h.CancelTask)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/tasks/t_foreign/cancel", nil),
		httptest.NewRequest(http.MethodGet, "/tasks/t_foreign/wait", nil),
	} {
		w := httptest.NewRecorder()
		owned.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("owner %s: status=%d", req.URL, w.Code)
		}
	}
}
