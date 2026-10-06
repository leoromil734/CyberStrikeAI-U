package handler

import (
	"bytes"
	"fmt"
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

func TestC2OnelinerRejectsInvalidCallbackAndUsesListenerScheme(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "callback.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	listener := &database.C2Listener{ID: "https", Name: "test", Type: "https_beacon", BindHost: "127.0.0.1", BindPort: 8443, ImplantToken: "test-only-token", CreatedAt: time.Now()}
	if err := db.CreateC2Listener(listener); err != nil {
		t.Fatal(err)
	}
	h := NewC2Handler(c2.NewManager(db, zap.NewNop(), t.TempDir()), zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "test-owner", Scope: database.RBACScopeAll})
	})
	r.POST("/oneliner", h.PayloadOneliner)
	// Inspect only the returned text. The generated command is never executed.
	for _, host := range []string{"bad host/abc", "https://example.com", "example.com:8443", "example.com", "::1"} {
		req := httptest.NewRequest(http.MethodPost, "/oneliner", bytes.NewBufferString(fmt.Sprintf(`{"listener_id":"https","kind":"curl_beacon","host":%q}`, host)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		valid := host == "example.com" || host == "::1"
		if !valid && w.Code != http.StatusBadRequest {
			t.Fatalf("invalid callback status: %d", w.Code)
		}
		if valid {
			if w.Code != http.StatusOK {
				t.Fatalf("valid callback status: %d", w.Code)
			}
			expected := "https://example.com:8443"
			if host == "::1" {
				expected = "https://[::1]:8443"
			}
			if !bytes.Contains(w.Body.Bytes(), []byte(expected)) {
				t.Fatal("scheme or IPv6 formatting lost")
			}
			if !bytes.Contains(w.Body.Bytes(), []byte("X-Session-Token")) {
				t.Fatal("HTTP template omitted session authentication")
			}
		}
	}
}
