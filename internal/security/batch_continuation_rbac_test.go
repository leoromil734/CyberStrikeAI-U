package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

func TestBatchConversationRoutesRequireBothPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, route := range []struct{ method, path, primary, additional string }{
		{http.MethodPost, "/api/batch-tasks/:queueId/tasks/:taskId/continue", "tasks:write", "chat:write"},
		{http.MethodGet, "/api/batch-tasks/:queueId/tasks/:taskId/original-message", "tasks:read", "chat:read"},
	} {
		for _, permissions := range []map[string]bool{
			{route.primary: true}, {route.additional: true}, {route.primary: true, route.additional: true},
		} {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(ContextSessionKey, Session{UserID: "operator", Scope: database.RBACScopeOwn, Permissions: permissions,
					PermissionScopes: map[string]string{route.primary: database.RBACScopeOwn, route.additional: database.RBACScopeAll}})
				c.Next()
			})
			router.Use(RBACMiddleware(nil))
			router.Handle(route.method, route.path, func(c *gin.Context) {
				s, _ := CurrentSession(c)
				if s.Scope != database.RBACScopeOwn || s.ScopeFor(route.additional) != database.RBACScopeAll {
					t.Fatal("additional conversation permission widened primary queue scope")
				}
				c.Status(http.StatusNoContent)
			})
			path := strings.ReplaceAll(strings.ReplaceAll(route.path, ":queueId", "queue"), ":taskId", "task")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(route.method, path, nil))
			want := http.StatusForbidden
			if permissions[route.primary] && permissions[route.additional] {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("%s %v: status %d, want %d: %s", route.path, permissions, w.Code, want, w.Body.String())
			}
		}
	}
}
