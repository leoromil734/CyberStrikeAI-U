package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func performResourceSecurityJSON(t *testing.T, router *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRoleSecurityRejectsFilenameCollisionsAndOverwrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Roles: map[string]config.RoleConfig{
		"existing_role": {Name: "existing_role", UserPrompt: "original", Enabled: true},
		"other":         {Name: "other", UserPrompt: "other original", Enabled: true},
	}}
	h := NewRoleHandler(cfg, filepath.Join(t.TempDir(), "config.yaml"), zap.NewNop())
	r := gin.New()
	r.POST("/roles", h.CreateRole)
	r.PUT("/roles/:name", h.UpdateRole)
	for _, name := range []string{"existing role", "EXISTING_ROLE", "../escape", "bad/name"} {
		w := performResourceSecurityJSON(t, r, http.MethodPost, "/roles", config.RoleConfig{Name: name, Enabled: true})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("unsafe create %q: %d", name, w.Code)
		}
	}
	w := performResourceSecurityJSON(t, r, http.MethodPut, "/roles/other", config.RoleConfig{Name: "existing_role", UserPrompt: "replacement"})
	if w.Code != http.StatusConflict || cfg.Roles["existing_role"].UserPrompt != "original" || cfg.Roles["other"].UserPrompt != "other original" || len(cfg.Roles) != 2 {
		t.Fatal("rename overwrote or removed an existing role")
	}
}

func TestMarkdownSecurityCreateAndUpdatePreserveFiles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	h := NewMarkdownAgentsHandler(dir)
	r := gin.New()
	r.POST("/agents", h.CreateMarkdownAgent)
	r.PUT("/agents/:filename", h.UpdateMarkdownAgent)
	body := markdownAgentBody{Filename: "first.md", ID: "shared", Name: "Review worker", Instruction: "Review the provided fixture."}
	w := performResourceSecurityJSON(t, r, http.MethodPost, "/agents", body)
	if w.Code != http.StatusOK {
		t.Fatalf("initial create: %d %s", w.Code, w.Body.String())
	}
	before, err := os.ReadFile(filepath.Join(dir, "first.md"))
	if err != nil {
		t.Fatal(err)
	}
	body.Instruction = "Replacement"
	w = performResourceSecurityJSON(t, r, http.MethodPost, "/agents", body)
	if w.Code != http.StatusConflict {
		t.Fatalf("existing filename accepted: %d", w.Code)
	}
	body.Filename = "second.md"
	w = performResourceSecurityJSON(t, r, http.MethodPost, "/agents", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate ID accepted: %d", w.Code)
	}
	body.Raw = "---\nid: ../unsafe\nname: Safe display\n---\nInstruction\n"
	w = performResourceSecurityJSON(t, r, http.MethodPut, "/agents/first.md", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid raw content accepted: %d", w.Code)
	}
	body.Raw = ""
	body.ID = "second"
	w = performResourceSecurityJSON(t, r, http.MethodPut, "/agents/missing.md", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("update created missing file: %d", w.Code)
	}
	after, err := os.ReadFile(filepath.Join(dir, "first.md"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected mutation changed the original file")
	}
	for _, filename := range []string{"second.md", "missing.md"} {
		if _, err := os.Stat(filepath.Join(dir, filename)); !os.IsNotExist(err) {
			t.Fatalf("rejected request created %s", filename)
		}
	}
}

func TestMarkdownSecurityConcurrentDuplicateID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewMarkdownAgentsHandler(t.TempDir())
	r := gin.New()
	r.POST("/agents", h.CreateMarkdownAgent)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, filename := range []string{"one.md", "two.md"} {
		wg.Add(1)
		go func(filename string) {
			defer wg.Done()
			body := markdownAgentBody{Filename: filename, ID: "same-id", Name: "Worker", Instruction: "Review a fixture."}
			codes <- performResourceSecurityJSON(t, r, http.MethodPost, "/agents", body).Code
		}(filename)
	}
	wg.Wait()
	close(codes)
	counts := make(map[int]int)
	for code := range codes {
		counts[code]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusBadRequest] != 1 {
		t.Fatalf("duplicate ID creation was not serialized: %v", counts)
	}
}

const resourceSecurityWorkflowGraph = `{"nodes":[{"id":"start-1","type":"start","label":"Start","position":{"x":0,"y":0},"config":{}},{"id":"out-1","type":"output","label":"Output","position":{"x":0,"y":120},"config":{"output_key":"result","source_binding":{"from":"inputs","field":"message"}}}],"edges":[{"id":"e1","source":"start-1","target":"out-1"}],"config":{"schema_version":1}}`

func TestWorkflowSecurityCreateCannotOverwriteAndEditCannotRename(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "workflow-api-security.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := NewWorkflowHandler(db, zap.NewNop())
	r := gin.New()
	r.POST("/workflows", h.Create)
	r.PUT("/workflows/:id", h.Update)
	body := workflowSaveRequest{ID: "original", Name: "Original", Graph: json.RawMessage(resourceSecurityWorkflowGraph)}
	w := performResourceSecurityJSON(t, r, http.MethodPost, "/workflows", body)
	if w.Code != http.StatusOK {
		t.Fatalf("initial create: %d %s", w.Code, w.Body.String())
	}
	body.Name = "Replacement"
	w = performResourceSecurityJSON(t, r, http.MethodPost, "/workflows", body)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create: %d", w.Code)
	}
	body.ID = "different"
	w = performResourceSecurityJSON(t, r, http.MethodPut, "/workflows/original", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("edit changed ID: %d", w.Code)
	}
	body.ID = "missing"
	w = performResourceSecurityJSON(t, r, http.MethodPut, "/workflows/missing", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("edit created missing definition: %d", w.Code)
	}
	body.ID = "../unsafe"
	w = performResourceSecurityJSON(t, r, http.MethodPost, "/workflows", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsafe ID accepted: %d", w.Code)
	}
	stored, err := db.GetWorkflowDefinition("original")
	if err != nil || stored == nil || stored.Name != "Original" || stored.Version != 1 {
		t.Fatal("rejected requests mutated the original definition")
	}
	// Historical IDs remain editable without being silently renamed.
	if err := db.UpsertWorkflowDefinition(&database.WorkflowDefinition{ID: "legacy.name", Name: "Legacy", GraphJSON: resourceSecurityWorkflowGraph}); err != nil {
		t.Fatal(err)
	}
	body.ID = "legacy.name"
	w = performResourceSecurityJSON(t, r, http.MethodPut, "/workflows/legacy.name", body)
	if w.Code != http.StatusOK {
		t.Fatalf("historical ID edit rejected: %d %s", w.Code, w.Body.String())
	}
}
