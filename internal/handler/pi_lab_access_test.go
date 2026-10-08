package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

func TestPILabPlatformHistoryHonorsCurrentProjectAccess(t *testing.T) {
	f := newPIPlatformFixture(t)
	manager := pilab.New(pilab.Options{Enabled: true, Root: t.TempDir(), Runtime: piHandlerFixtureRuntime{}})
	defer manager.Close()
	h := NewPILabHandler(manager, nil)
	h.SetPlatform(f.platform)
	c, _ := f.ginContext()
	req := f.request()
	req.Title = "PRIVATE_PROJECT_TITLE"
	run, err := manager.CreatePrepared(f.session.UserID, req, pilab.Model{Provider: "openai", ID: "fixture", APIKey: "fixture-only"}, f.platform.Preparer(c))
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		session, ok := f.auth.ValidateToken(f.session.Token)
		if !ok {
			c.AbortWithStatus(401)
			return
		}
		c.Set(security.ContextSessionKey, session)
		c.Next()
	})
	router.GET("/runs", h.List)
	router.GET("/runs/:id", h.Get)
	router.GET("/runs/:id/events", h.Events)
	router.POST("/runs/:id/cancel", h.Cancel)
	request := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	if w := request("GET", "/runs/"+run.ID); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := f.db.UpsertRBACRole(f.roleID, "pi-tester", "", database.RBACScopeOwn, []string{"agent:execute", "chat:write"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/runs/" + run.ID, "/runs/" + run.ID + "/events"} {
		if w := request(http.MethodGet, path); w.Code != 403 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := request("GET", "/runs")
	if w.Code != 200 || strings.Contains(w.Body.String(), run.ID) {
		t.Fatal(w.Code, w.Body.String())
	}
	// Revocation must not prevent an owner from stopping their costly job, but
	// the cancellation response must not disclose the revoked project data.
	w = request("POST", "/runs/"+run.ID+"/cancel")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var cancelled pilab.Run
	if err := json.Unmarshal(w.Body.Bytes(), &cancelled); err != nil {
		t.Fatal(err)
	}
	if cancelled.Status != "cancelled" || cancelled.ProjectID != "" || cancelled.Report != "" || strings.Contains(w.Body.String(), req.Title) {
		t.Fatal(w.Body.String())
	}
	manager.Close()
}

func TestPILabProbeReadDoesNotRequireAPlatformBinding(t *testing.T) {
	h := NewPILabHandler(pilab.New(pilab.Options{Root: t.TempDir()}), nil)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/runs", nil)
	if !h.canReadRun(c, pilab.Run{Mode: pilab.ModeProbe}) {
		t.Fatal("probe history must remain compatible")
	}
	if h.canReadRun(c, pilab.Run{Mode: pilab.ModePlatform, ProjectID: "unbound"}) {
		t.Fatal("platform history failed open")
	}
}
