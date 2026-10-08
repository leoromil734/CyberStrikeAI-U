package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

type piHandlerFixtureRuntime struct{}

func (piHandlerFixtureRuntime) Check(context.Context) error { return nil }
func (piHandlerFixtureRuntime) Run(ctx context.Context, _ string, _ pilab.Input, emit func(pilab.Event) error) error {
	<-ctx.Done()
	return ctx.Err()
}

func piFixtureRouter(h *PILabHandler, owner string, allowed bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if owner != "" {
			c.Set(security.ContextSessionKey, security.Session{UserID: owner, Permissions: map[string]bool{"agent:execute": allowed}})
		}
		c.Next()
	})
	r.GET("/status", h.Status)
	r.GET("/runs", h.List)
	r.POST("/runs", h.Create)
	r.GET("/runs/:id", h.Get)
	r.GET("/runs/:id/events", h.Events)
	r.POST("/runs/:id/cancel", h.Cancel)
	return r
}
func piRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestPILabHTTPAuthOwnershipAndCredentialBoundary(t *testing.T) {
	manager := pilab.New(pilab.Options{Enabled: true, Root: t.TempDir(), Runtime: piHandlerFixtureRuntime{}})
	defer manager.Close()
	resolver := func(string) (pilab.Model, string, error) {
		return pilab.Model{Provider: "openai", ID: "fixture", APIKey: "never-public-key"}, "default", nil
	}
	h := NewPILabHandler(manager, resolver)
	if w := piRequest(piFixtureRouter(h, "", true), "GET", "/status", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := piRequest(piFixtureRouter(h, "alice", false), "GET", "/status", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	alice := piFixtureRouter(h, "alice", true)
	w := piRequest(alice, "POST", "/runs", `{"title":"fixture","prompt":"offline fixture","scope":["https://example.test"],"authorized":true}`)
	if w.Code != http.StatusAccepted || strings.Contains(w.Body.String(), "never-public-key") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	var run pilab.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	bob := piFixtureRouter(h, "bob", true)
	for _, endpoint := range []struct{ method, path string }{{"GET", "/runs/" + run.ID}, {"GET", "/runs/" + run.ID + "/events"}, {"POST", "/runs/" + run.ID + "/cancel"}} {
		if w := piRequest(bob, endpoint.method, endpoint.path, ""); w.Code != 404 {
			t.Fatal("cross-owner access", endpoint, w.Code)
		}
	}
	w = piRequest(bob, "GET", "/runs", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), run.ID) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = piRequest(alice, "GET", "/runs/"+run.ID+"/events?after=oops", "")
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = piRequest(alice, "POST", "/runs/"+run.ID+"/cancel", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "cancelled") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestPILabRejectsOversizedUnauthorizedAndUnknownChannel(t *testing.T) {
	manager := pilab.New(pilab.Options{Root: t.TempDir()})
	defer manager.Close()
	h := NewPILabHandler(manager, nil)
	r := piFixtureRouter(h, "alice", true)
	for _, body := range []string{`{"title":"missing authorization","prompt":"fixture","scope":["https://example.test"]}`, strings.Repeat(" ", 33*1024) + `{}`, `{"scope":["http://localhost"]}`} {
		w := piRequest(r, "POST", "/runs", body)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	cfg := &config.Config{AI: config.AIConfig{DefaultChannel: "main", Channels: map[string]config.AIChannelConfig{"main": {Provider: "openai", Model: "test-model", APIKey: "private-key"}}}}
	configHandler := &ConfigHandler{config: cfg}
	if _, _, err := configHandler.ResolvePILabModel("missing"); err == nil {
		t.Fatal("unknown channel silently fell back")
	}
	model, id, err := configHandler.ResolvePILabModel("")
	if err != nil || id != "main" || model.ID != "test-model" {
		t.Fatal(model.ID, id, err)
	}
	cfg.AI.Channels["main"] = config.AIChannelConfig{Model: "changed", APIKey: "changed-key"}
	if model.ID != "test-model" || model.APIKey != "private-key" {
		t.Fatal("run snapshot changed with config")
	}
}
