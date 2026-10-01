package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/experience"
	em "cyberstrike-ai/internal/experience/model"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func experienceAPIFixture(t *testing.T) (*gin.Engine, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "experience-api.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Now()
	end := now.Add(time.Second)
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "proof", OwnerUserID: "u1", ToolName: "scanner", Status: mcp.ToolExecutionStatusCompleted, StartTime: now, EndTime: &end}); err != nil {
		t.Fatal(err)
	}
	h := NewExperienceHandler(experience.New(db, zap.NewNop()), db, nil, zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) {
		p, ok := authctx.PrincipalFromContext(c.Request.Context())
		if ok {
			c.Set(security.ContextSessionKey, security.Session{UserID: p.UserID, Username: p.Username, Scope: p.Scope, Permissions: p.Permissions, PermissionScopes: p.PermissionScopes})
		}
		c.Next()
	})
	r.Use(security.RBACMiddleware(db))
	r.GET("/api/experiences", h.List)
	r.POST("/api/experiences", h.Create)
	r.GET("/api/experiences/:id", h.Get)
	r.PUT("/api/experiences/:id", h.Revise)
	r.POST("/api/experiences/:id/review", h.Review)
	r.GET("/api/experiences/:id/evidence/:executionId", h.Evidence)
	return r, db
}
func experienceAPICall(t *testing.T, r http.Handler, p authctx.Principal, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authctx.WithPrincipal(context.Background(), p))
	out := httptest.NewRecorder()
	r.ServeHTTP(out, req)
	return out
}
func apiMemoryPrincipal(user string, review bool) authctx.Principal {
	permissions := map[string]bool{"experience:read": true, "experience:write": true, "monitor:read": true}
	scope := database.RBACScopeOwn
	if review {
		scope = database.RBACScopeAll
		permissions["experience:review"] = true
		permissions["experience:share"] = true
	}
	return authctx.NewPrincipal(user, user, scope, permissions)
}
func apiMemoryProposal() em.Proposal {
	return em.Proposal{Content: em.Content{Kind: em.KindWorkflow, Title: "reviewed workflow", Summary: "parameterized reusable method", Steps: []string{"check {{target}}"}, Verification: "compare actual output with baseline"}, Evidence: []em.Evidence{{ExecutionID: "proof", Role: "validation"}}}
}

func TestExperienceAPIPermissionsAndPublicationBoundary(t *testing.T) {
	r, _ := experienceAPIFixture(t)
	owner := apiMemoryPrincipal("u1", false)
	proposal := apiMemoryProposal()
	b, _ := json.Marshal(proposal)
	var forged map[string]interface{}
	json.Unmarshal(b, &forged)
	forged["status"] = "verified"
	forged["scope"] = "shared"
	forged["owner_user_id"] = "u2"
	response := experienceAPICall(t, r, owner, http.MethodPost, "/api/experiences", forged)
	if response.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", response.Code, response.Body.String())
	}
	var entry em.Entry
	if err := json.Unmarshal(response.Body.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Status != em.StatusCandidate || entry.Scope != em.ScopePrivate || entry.OwnerUserID != "u1" {
		t.Fatal("caller-controlled publication or ownership accepted")
	}
	path := "/api/experiences/" + entry.ID
	if response := experienceAPICall(t, r, apiMemoryPrincipal("u2", false), http.MethodGet, path, nil); response.Code != http.StatusNotFound {
		t.Fatal("foreign private entry visible")
	}
	review := em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "verified actual execution and baseline"}
	if response := experienceAPICall(t, r, owner, http.MethodPost, path+"/review", review); response.Code != http.StatusForbidden {
		t.Fatal("ordinary operator could review")
	}
	limited := apiMemoryPrincipal("u1", true)
	delete(limited.Permissions, "experience:share")
	if response := experienceAPICall(t, r, limited, http.MethodPost, path+"/review", review); response.Code != http.StatusForbidden {
		t.Fatal("review permission widened sharing")
	}
	if response := experienceAPICall(t, r, apiMemoryPrincipal("admin", true), http.MethodPost, path+"/review", review); response.Code != http.StatusOK {
		t.Fatalf("review: %d %s", response.Code, response.Body.String())
	}
	if response := experienceAPICall(t, r, apiMemoryPrincipal("u2", false), http.MethodGet, path+"/evidence/proof", nil); response.Code != http.StatusForbidden {
		t.Fatal("shared method leaked raw proof")
	}
	if response := experienceAPICall(t, r, owner, http.MethodGet, path+"/evidence/proof", nil); response.Code != http.StatusOK {
		t.Fatal("owner could not read proof")
	}
}
func TestExperienceAPIRejectsStaleReviewAndOversizedBodies(t *testing.T) {
	r, _ := experienceAPIFixture(t)
	owner := apiMemoryPrincipal("u1", false)
	response := experienceAPICall(t, r, owner, http.MethodPost, "/api/experiences", apiMemoryProposal())
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	var entry em.Entry
	json.Unmarshal(response.Body.Bytes(), &entry)
	path := "/api/experiences/" + entry.ID
	p := apiMemoryProposal()
	p.Content.Steps = []string{"new version"}
	body := map[string]interface{}{"content": p.Content, "evidence": p.Evidence, "revision": 1}
	if response := experienceAPICall(t, r, owner, http.MethodPut, path, body); response.Code != http.StatusOK {
		t.Fatalf("revise: %s", response.Body.String())
	}
	if response := experienceAPICall(t, r, apiMemoryPrincipal("admin", true), http.MethodPost, path+"/review", em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopePrivate, Note: "stale"}); response.Code != http.StatusConflict {
		t.Fatal("stale review allowed")
	}
	p.Content.Summary = strings.Repeat("x", 400*1024)
	if response := experienceAPICall(t, r, owner, http.MethodPost, "/api/experiences", p); response.Code != http.StatusBadRequest {
		t.Fatal("oversized body accepted")
	}
}
