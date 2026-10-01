package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newPrivateBatchHandler(t *testing.T) (*AgentHandler, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "private-batch.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	owner, err := db.CreateRBACUser("batch-owner", "Batch owner", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewBatchTaskManager(zap.NewNop())
	manager.SetDB(db)
	return &AgentHandler{db: db, logger: zap.NewNop(), batchTaskManager: manager,
		config: &config.Config{Project: config.ProjectConfig{Enabled: true, DefaultProjectID: "shared-default"}}}, owner.ID
}

func TestBatchTaskProjectSelectionNeverFallsBackForPrivateMode(t *testing.T) {
	cfg := &config.Config{Project: config.ProjectConfig{Enabled: true, DefaultProjectID: "shared-default"}}
	queue := &BatchTaskQueue{IndependentProjects: true, ProjectID: "shared-queue"}
	task := &BatchTask{ProjectID: "private-task"}
	if got, err := batchSubTaskProjectID(cfg, queue, task); err != nil || got != "private-task" {
		t.Fatalf("private task selected shared context: %q %v", got, err)
	}
	task.ProjectID = ""
	if got, err := batchSubTaskProjectID(cfg, queue, task); err == nil || got != "" {
		t.Fatalf("missing private project fell back to shared: %q %v", got, err)
	}
	cfg.Project.Enabled = false
	task.ProjectID = "private-task"
	if _, err := batchSubTaskProjectID(cfg, queue, task); err == nil {
		t.Fatal("disabled project feature silently removed private context")
	}
	cfg.Project.Enabled = true
	queue.IndependentProjects = false
	if got, err := batchSubTaskProjectID(cfg, queue, task); err != nil || got != "shared-queue" {
		t.Fatalf("legacy shared mode changed: %q %v", got, err)
	}
	queue.ProjectID = ""
	if got, err := batchSubTaskProjectID(cfg, queue, task); err != nil || got != "shared-default" {
		t.Fatalf("legacy default project behaviour changed: %q %v", got, err)
	}
}

func TestPrivateBatchProjectsPersistAcrossReloadAndRerun(t *testing.T) {
	h, owner := newPrivateBatchHandler(t)
	queue, err := h.batchTaskManager.CreateBatchQueue("isolation", "", "deep", "manual", "", "", nil, 2, 0,
		batchTaskInputs("test one.example.com", "test two.example.com"), database.BatchQueueCreateOptions{IndependentProjects: true, OwnerUserID: owner})
	if err != nil {
		t.Fatal(err)
	}
	if !queue.IndependentProjects || queue.ProjectID != "" || len(queue.Tasks) != 2 || queue.Tasks[0].ProjectID == queue.Tasks[1].ProjectID {
		t.Fatalf("private projects not allocated: %+v", queue)
	}
	cold := NewBatchTaskManager(zap.NewNop())
	cold.SetDB(h.db)
	loaded, ok := cold.GetBatchQueue(queue.ID)
	if !ok || !loaded.IndependentProjects || loaded.Tasks[0].ProjectID != queue.Tasks[0].ProjectID || loaded.Tasks[0].ProjectName != queue.Tasks[0].ProjectName {
		t.Fatalf("restart lost task project identity: %+v", loaded)
	}
	if !cold.ResetQueueForRerun(queue.ID) {
		t.Fatal("could not prepare rerun")
	}
	rerun, _ := cold.GetBatchQueue(queue.ID)
	if rerun.Tasks[0].ProjectID != queue.Tasks[0].ProjectID || rerun.Tasks[1].ProjectID != queue.Tasks[1].ProjectID {
		t.Fatal("rerun allocated new/shared projects instead of reusing private context")
	}
	added, err := cold.AddTaskToQueue(queue.ID, "test three.example.com", "")
	if err != nil || added.ProjectID == "" || added.ProjectID == rerun.Tasks[0].ProjectID {
		t.Fatalf("appended task missing private context: %v %+v", err, added)
	}
	oldProjectID := rerun.Tasks[0].ProjectID
	if err := cold.UpdateTaskMessage(queue.ID, rerun.Tasks[0].ID, "test changed.example.com"); err != nil {
		t.Fatal(err)
	}
	changed, _ := cold.GetBatchQueue(queue.ID)
	if changed.Tasks[0].ProjectID == oldProjectID || changed.Tasks[1].ProjectID != rerun.Tasks[1].ProjectID {
		t.Fatal("changing a target reused polluted context or changed a sibling project")
	}
	if _, err := h.db.GetProject(oldProjectID); err != nil {
		t.Fatal("target edit deleted the historical project")
	}
}

func TestCreateBatchQueueHTTPPrivateProjectsRequirePermission(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		h, owner := newPrivateBatchHandler(t)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Set(security.ContextSessionKey, security.Session{UserID: owner, Scope: database.RBACScopeAll,
			Permissions: map[string]bool{"tasks:write": true, "project:write": allowed}})
		c.Request = httptest.NewRequest(http.MethodPost, "/api/batch-tasks", strings.NewReader(`{"title":"private","tasks":["test one.example.com","test two.example.com"],"independentProjects":true}`))
		c.Request.Header.Set("Content-Type", "application/json")
		h.CreateBatchQueue(c)
		if !allowed {
			if recorder.Code != http.StatusForbidden || len(h.batchTaskManager.GetLoadedQueues()) != 0 {
				t.Fatalf("unprivileged task creation mutated projects/queues: %d %s", recorder.Code, recorder.Body.String())
			}
			continue
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("private HTTP creation rejected: %d %s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Queue *BatchTaskQueue `json:"queue"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.Queue == nil || !response.Queue.IndependentProjects || response.Queue.Tasks[0].ProjectID == "" {
			t.Fatalf("HTTP response omits private binding: err=%v body=%s", err, recorder.Body.String())
		}
	}
}

func TestCreateBatchQueueMCPPrivateProjectsRequirePermission(t *testing.T) {
	h, owner := newPrivateBatchHandler(t)
	server := mcp.NewServer(zap.NewNop())
	// The tool server is fail-closed for attributed calls; this test supplies
	// the tasks policy and separately exercises project-write enforcement.
	server.SetToolAuthorizer(func(context.Context, string, map[string]interface{}) error { return nil })
	RegisterBatchTaskMCPTools(server, h, zap.NewNop())
	args := map[string]interface{}{"tasks": []interface{}{"test example.com"}, "independent_projects": true}
	for _, allowed := range []bool{false, true} {
		principal := authctx.NewPrincipalWithScopes(owner, "owner", database.RBACScopeAll,
			map[string]bool{"tasks:write": true, "project:write": allowed}, nil)
		result, _, err := server.CallTool(authctx.WithPrincipal(context.Background(), principal), builtin.ToolBatchTaskCreate, args)
		if err != nil || result == nil || result.IsError == allowed {
			t.Fatalf("private MCP permission result wrong: allowed=%v err=%v result=%+v", allowed, err, result)
		}
	}
	queues := h.batchTaskManager.GetLoadedQueues()
	if len(queues) != 1 || !queues[0].IndependentProjects || queues[0].Tasks[0].ProjectID == "" {
		t.Fatalf("MCP did not persist per-task project: %+v", queues)
	}
}
