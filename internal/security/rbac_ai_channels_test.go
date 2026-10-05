package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
)

func TestAIChannelsPickerPermissionBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, permission, method, path string
		want                           int
	}{
		{"chat-reader", "chat:read", http.MethodGet, "/api/config/ai-channels", http.StatusOK},
		{"task-reader", "tasks:read", http.MethodGet, "/api/config/ai-channels", http.StatusOK},
		{"admin-reader", "config:read", http.MethodGet, "/api/config/ai-channels", http.StatusOK},
		{"head-reader", "tasks:read", http.MethodHead, "/api/config/ai-channels", http.StatusOK},
		{"unrelated-reader", "project:read", http.MethodGet, "/api/config/ai-channels", http.StatusForbidden},
		{"no-session", "", http.MethodGet, "/api/config/ai-channels", http.StatusForbidden},
		{"private-records", "chat:read", http.MethodGet, "/api/config/ai-channel-probes", http.StatusForbidden},
		{"private-config", "tasks:read", http.MethodGet, "/api/config", http.StatusForbidden},
		{"test-requires-write", "tasks:read", http.MethodPost, "/api/config/ai-channels/:id/test", http.StatusForbidden},
		{"config-reader-cannot-test", "config:read", http.MethodPost, "/api/config/ai-channels/:id/test", http.StatusForbidden},
		{"config-writer-can-test", "config:write", http.MethodPost, "/api/config/ai-channels/:id/test", http.StatusOK},
		{"no-prefix-expansion", "chat:read", http.MethodGet, "/api/config/ai-channels/:id/private", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				if tc.permission != "" {
					c.Set(ContextSessionKey, Session{
						UserID: "picker", Permissions: map[string]bool{tc.permission: true}, Scope: database.RBACScopeOwn,
					})
				}
				c.Next()
			})
			router.Use(RBACMiddleware(nil))
			router.Handle(tc.method, tc.path, func(c *gin.Context) { c.Status(http.StatusOK) })
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
