package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/workspaceguard"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type piPlatformFixture struct {
	platform *PILabPlatform
	db       *database.DB
	cfg      *config.Config
	server   *mcp.Server
	auth     *security.AuthManager
	session  security.Session
	project  *database.Project
	roleID   string
}

var piPlatformTestPermissions = []string{"agent:execute", "agent:local-execute", "chat:write", "project:read", "project:write", "monitor:read", "monitor:write"}

func newPIPlatformFixture(t *testing.T, permissions ...string) *piPlatformFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	db, err := database.NewDB(filepath.Join(root, "pi.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = db.BootstrapRBAC("test-only-unused-admin-hash", security.PermissionCatalog); err != nil {
		t.Fatal(err)
	}
	if permissions == nil {
		permissions = piPlatformTestPermissions
	}
	role, err := db.UpsertRBACRole("", "pi-tester", "", database.RBACScopeOwn, permissions)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := security.HashPassword("PI-fixture-only-password-42!")
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateRBACUser("pi-fixture", "PI", hash, true, []string{role.ID})
	if err != nil {
		t.Fatal(err)
	}
	auth := security.NewAuthManager(1)
	if _, err = auth.AttachRBACStore(db); err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.Authenticate(user.Username, "PI-fixture-only-password-42!")
	if err != nil {
		t.Fatal(err)
	}
	session, ok := auth.ValidateToken(token)
	if !ok {
		t.Fatal("fixture login")
	}
	project, err := db.CreateProject(&database.Project{Name: "PI offline fixture", ScopeJSON: `{"allow":["fixture.invalid"],"exclude":["payments"]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SetResourceOwner("project", project.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{SkillsDir: filepath.Join(root, "skills"), Roles: map[string]config.RoleConfig{piPlatformRole: {Name: piPlatformRole, Enabled: true, Description: "离线角色元数据", UserPrompt: "ROLE_SNAPSHOT_ONLY\n技能路由：pentest-agent-os。", Tools: []string{"exec", "not_registered"}}}}
	cfg.Agent.WorkspaceRootDir = filepath.Join(root, "workspace")
	cfg.MultiAgent.EinoMiddleware.ReductionRootDir = filepath.Join(root, "evidence")
	cfg.OpenAI.APIKey = "must-never-leak-test-key"
	piPlatformWriteFixture(t, filepath.Join(cfg.SkillsDir, "pentest-agent-os", "SKILL.md"), "---\nname: pentest-agent-os\ndescription: Offline skill metadata\n---\nSKILL_BODY_ONLY\n")
	piPlatformWriteFixture(t, filepath.Join(cfg.SkillsDir, "pentest-agent-os", "references", "fixture.md"), "REFERENCED_SKILL_TEXT")
	server := mcp.NewServerWithStorage(zap.NewNop(), db)
	server.ConfigureToolResultSpillRoot(cfg.MultiAgent.EinoMiddleware.ReductionRootDir)
	server.SetToolAuthorizer(func(ctx context.Context, _ string, _ map[string]interface{}) error {
		p, ok := authctx.PrincipalFromContext(ctx)
		if !ok || !p.HasPermission("agent:local-execute") {
			return errors.New("test underlying authorization denied")
		}
		return nil
	})
	server.RegisterTool(mcp.Tool{Name: "exec", Description: "Fixture only; never invokes a process", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"project_id": map[string]interface{}{"type": "string"}, "conversation_id": map[string]interface{}{"type": "string"}, "source_conversation_id": map[string]interface{}{"type": "string"}, "source_message_id": map[string]interface{}{"type": "string"}, "input": map[string]interface{}{"type": "string", "default": "must-never-leak-schema-key"}}}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "offline fixture result"}}}, nil
	})
	for _, name := range []string{"unlisted_tool", "c2_task", "batch_task_create", "temporary_email", "upsert_finding_candidate"} {
		server.RegisterTool(mcp.Tool{Name: name, InputSchema: map[string]interface{}{"type": "object"}}, func(context.Context, map[string]interface{}) (*mcp.ToolResult, error) { return &mcp.ToolResult{}, nil })
	}
	agent := &AgentHandler{db: db, tasks: NewAgentTaskManager(), logger: zap.NewNop()}
	p := NewPILabPlatform(&ConfigHandler{config: cfg}, agent, db, server, nil, auth, zap.NewNop())
	return &piPlatformFixture{platform: p, db: db, cfg: cfg, server: server, auth: auth, session: session, project: project, roleID: role.ID}
}
func piPlatformWriteFixture(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func (f *piPlatformFixture) ginContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/pi-lab/runs", nil)
	c.Set(security.ContextSessionKey, f.session)
	c.Set(security.ContextAuthTokenKey, f.session.Token)
	return c, w
}
func (f *piPlatformFixture) request() pilab.CreateRequest {
	return pilab.CreateRequest{Mode: pilab.ModePlatform, ProjectID: f.project.ID, Authorized: true, Prompt: "只处理离线 fixture，不访问网络。", Scope: []string{"https://fixture.invalid/specific/path"}}
}
func (f *piPlatformFixture) prepare(t *testing.T) *pilab.PreparedRun {
	t.Helper()
	c, _ := f.ginContext()
	run, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(run.Close)
	ctx, cancel := context.WithCancel(run.Context)
	t.Cleanup(cancel)
	if err = run.Start(ctx, cancel); err != nil {
		t.Fatal(err)
	}
	return run
}
func piPlatformReplyText(reply *pilab.ToolReply) string {
	if reply == nil {
		return ""
	}
	var text strings.Builder
	for _, c := range reply.Content {
		text.WriteString(c.Text)
	}
	return text.String()
}

func TestPILabPlatformProfileAndRoleSnapshot(t *testing.T) {
	f := newPIPlatformFixture(t)
	c, w := f.ginContext()
	f.platform.Profile(c)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var profile pilab.Profile
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	if !profile.Available || profile.Role.Name != piPlatformRole || profile.Limits.MaxToolCalls != 2000 || profile.Limits.MaxTurns != 500 {
		t.Fatalf("profile: %+v", profile)
	}
	for _, private := range []string{f.session.Token, f.cfg.SkillsDir, "ROLE_SNAPSHOT_ONLY", "SKILL_BODY_ONLY", "must-never-leak-test-key", "must-never-leak-schema-key"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatalf("private profile content: %s", private)
		}
	}
	names := map[string]bool{}
	for _, tool := range profile.Tools {
		names[tool.Name] = true
		if tool.InputSchema["type"] != "object" {
			t.Fatal("non-object schema")
		}
	}
	for _, name := range []string{"exec", "load_skill", "read_skill_file", "read_file", "write_file", "temporary_email", "upsert_finding_candidate"} {
		if !names[name] {
			t.Fatalf("missing %s", name)
		}
	}
	for _, name := range []string{"not_registered", "unlisted_tool", "c2_task", "batch_task_create"} {
		if names[name] {
			t.Fatalf("unexpected %s", name)
		}
	}
	run := f.prepare(t)
	if !strings.Contains(run.Platform.Instructions, "ROLE_SNAPSHOT_ONLY") || !strings.Contains(run.Platform.WorkerInstructions, "ROLE_SNAPSHOT_ONLY") || !strings.Contains(run.Platform.Instructions, "specific/path") || !strings.Contains(run.Platform.Instructions, "payments") {
		t.Fatal("role or scope missing")
	}
	wire, _ := json.Marshal(run.Platform)
	if strings.Contains(string(wire), f.session.Token) || strings.Contains(string(wire), f.cfg.OpenAI.APIKey) {
		t.Fatal("credentials sent to runtime")
	}
	f.platform.config.mu.Lock()
	role := f.cfg.Roles[piPlatformRole]
	role.UserPrompt = "NEW_ROLE"
	f.cfg.Roles[piPlatformRole] = role
	f.platform.config.mu.Unlock()
	if strings.Contains(run.Platform.Instructions, "NEW_ROLE") {
		t.Fatal("mutable role snapshot")
	}
}

func TestPILabPlatformRejectsPermissionsRoleAndProject(t *testing.T) {
	for _, missing := range piPlatformTestPermissions[:5] {
		t.Run(missing, func(t *testing.T) {
			var permissions []string
			for _, p := range piPlatformTestPermissions {
				if p != missing {
					permissions = append(permissions, p)
				}
			}
			f := newPIPlatformFixture(t, permissions...)
			c, w := f.ginContext()
			f.platform.Profile(c)
			if w.Code != http.StatusForbidden {
				t.Fatal(w.Code)
			}
			_, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), f.request())
			if !errors.Is(err, pilab.ErrForbidden) {
				t.Fatalf("expected forbidden: %v", err)
			}
			var count int
			_ = f.db.QueryRow("SELECT COUNT(*) FROM conversations").Scan(&count)
			if count != 0 {
				t.Fatal("unauthorized conversation created")
			}
		})
	}
	f := newPIPlatformFixture(t)
	for _, mutate := range []func(*pilab.CreateRequest){func(r *pilab.CreateRequest) { r.Authorized = false }, func(r *pilab.CreateRequest) { r.ProjectID = "" }, func(r *pilab.CreateRequest) { r.ProjectID = "foreign" }, func(r *pilab.CreateRequest) { r.Role = "默认" }, func(r *pilab.CreateRequest) { r.Mode = pilab.ModeProbe }} {
		req := f.request()
		mutate(&req)
		c, _ := f.ginContext()
		if _, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), req); !errors.Is(err, pilab.ErrForbidden) {
			t.Fatalf("unexpected error %v", err)
		}
	}
	f.platform.config.mu.Lock()
	role := f.cfg.Roles[piPlatformRole]
	role.Enabled = false
	f.cfg.Roles[piPlatformRole] = role
	f.platform.config.mu.Unlock()
	c, _ := f.ginContext()
	if _, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), f.request()); !errors.Is(err, pilab.ErrPlatformUnavailable) {
		t.Fatalf("disabled role fallback: %v", err)
	}
}

func TestPILabPlatformCopiesGinAndRejectsIdentityInjection(t *testing.T) {
	f := newPIPlatformFixture(t)
	c, _ := f.ginContext()
	requestCtx, cancelRequest := context.WithCancel(c.Request.Context())
	c.Request = c.Request.WithContext(requestCtx)
	prepare := f.platform.Preparer(c)
	c.Set(security.ContextSessionKey, security.Session{})
	c.Set(security.ContextAuthTokenKey, "")
	cancelRequest()
	run, err := prepare(context.Background(), uuid.NewString(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	ctx, cancel := context.WithCancel(run.Context)
	defer cancel()
	if err = run.Start(ctx, cancel); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]interface{}{{"project_id": "foreign"}, {"conversation_id": "foreign"}, {"source_conversation_id": "foreign"}, {"source_message_id": "foreign"}, {"projectId": "foreign"}, {"execution_id": "foreign"}} {
		if _, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec", Arguments: args}); !errors.Is(err, pilab.ErrForbidden) {
			t.Fatalf("injection admitted %+v: %v", args, err)
		}
	}
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || reply.IsError || reply.ExecutionID == "" {
		t.Fatalf("request cancellation affected run: %+v %v", reply, err)
	}
	record, err := f.db.GetToolExecution(reply.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if record.ConversationID != run.Platform.ConversationID || record.OwnerUserID != f.session.UserID || record.Arguments["project_id"] != f.project.ID || record.Arguments["source_conversation_id"] != run.Platform.ConversationID {
		t.Fatalf("identity: %+v", record)
	}
	f.auth.RevokeToken(f.session.Token)
	if _, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"}); !errors.Is(err, pilab.ErrForbidden) {
		t.Fatalf("revoked session used: %v", err)
	}
}

func TestPILabPlatformRechecksRBACAndBinding(t *testing.T) {
	for _, change := range []string{"permission", "project-binding", "ownership"} {
		t.Run(change, func(t *testing.T) {
			f := newPIPlatformFixture(t)
			run := f.prepare(t)
			switch change {
			case "permission":
				_, err := f.db.UpsertRBACRole(f.roleID, "pi-tester", "", database.RBACScopeOwn, []string{"agent:execute", "chat:write", "project:read", "project:write"})
				if err != nil {
					t.Fatal(err)
				}
			case "project-binding":
				other, err := f.db.CreateProject(&database.Project{Name: "other"})
				if err != nil {
					t.Fatal(err)
				}
				if err = f.db.SetConversationProjectID(run.Platform.ConversationID, other.ID); err != nil {
					t.Fatal(err)
				}
			case "ownership":
				if _, err := f.db.Exec("UPDATE projects SET owner_user_id = ? WHERE id = ?", "someone-else", f.project.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"}); !errors.Is(err, pilab.ErrForbidden) {
				t.Fatalf("boundary changed: %v", err)
			}
		})
	}
}

func TestPILabPlatformMCPStorageObserverAndBudget(t *testing.T) {
	f := newPIPlatformFixture(t)
	var observed atomic.Bool
	var expectedConv string
	f.server.SetExecutionObserver(func(ctx context.Context, e *mcp.ToolExecution) {
		if e.Status != "completed" {
			return
		}
		p, ok := authctx.PrincipalFromContext(ctx)
		policy := workspaceguard.FromContext(ctx)
		if ok && p.UserID == f.session.UserID && e.OwnerUserID == p.UserID && e.ConversationID == expectedConv && mcp.MCPProjectIDFromContext(ctx) == f.project.ID && mcp.MCPExecutionIDFromContext(ctx) == e.ID && policy != nil && mcp.AgentRunBudgetFromContext(ctx) != nil {
			// Persist the same ingestion partition used by the production result
			// observer, without starting its workers or any scanner.
			assessment, err := f.db.LatestAssessmentRun(expectedConv)
			if err != nil || assessment == nil {
				t.Error("missing assessment identity")
				return
			}
			meta := evidence.Execution{ID: e.ID, Access: evidence.Access{Owner: p.UserID, ProjectID: f.project.ID, ConversationID: expectedConv}, AssessmentID: assessment.AssessmentID, Tool: e.ToolName, Status: e.Status, Completion: evidence.Complete}
			if err := f.db.SetResultIngestionState(evidence.WithAccess(ctx, meta.Access), meta, "pending", ""); err != nil {
				t.Error(err)
				return
			}
			observed.Store(true)
		}
	})
	definition := f.server.GetAllTools()
	var execDef mcp.Tool
	for _, d := range definition {
		if d.Name == "exec" {
			execDef = d
		}
	}
	f.server.RegisterTool(execDef, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if err := mcp.AdmitProjectFactWrite(ctx, 1); err != nil {
			return nil, err
		}
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: strings.Repeat("FULL_ORIGINAL\n", 5000)}, {Type: "image", Text: "must-not-be-sent-as-image"}}}, nil
	})
	run := f.prepare(t)
	expectedConv = run.Platform.ConversationID
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || reply.IsError || reply.ExecutionID == "" {
		t.Fatalf("execution: %+v %v", reply, err)
	}
	if !observed.Load() {
		t.Fatal("existing result-pipeline observer lost trusted identity/budget")
	}
	job, err := f.db.ResultIngestionJob(context.Background(), reply.ExecutionID)
	if err != nil || job.ExecutionID != reply.ExecutionID || job.ProjectID != f.project.ID || job.ConversationID != expectedConv || job.Owner != f.session.UserID || job.State != "pending" {
		t.Fatalf("result pipeline partition mismatch: %+v %v", job, err)
	}
	record, err := f.db.GetToolExecution(reply.ExecutionID)
	if err != nil || record.Status != "completed" || record.ConversationID != expectedConv {
		t.Fatalf("persisted execution: %+v %v", record, err)
	}
	text := piPlatformReplyText(reply)
	if len(text) > 15000 || !strings.Contains(text, "persisted-output") {
		t.Fatal("large tool result did not use existing artifact spill")
	}
	for _, content := range reply.Content {
		if content.Type != "text" {
			t.Fatal("non-text result forwarded")
		}
	}
	policy := workspaceguard.FromContext(run.Context)
	var original string
	_ = filepath.WalkDir(policy.EvidenceRoot, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(path)
			if strings.Contains(string(data), strings.Repeat("FULL_ORIGINAL\n", 3000)) {
				original = path
			}
		}
		return nil
	})
	if original == "" {
		t.Fatal("original was not saved to authorized evidence root")
	}
	read, err := run.Execute(context.Background(), pilab.ToolCall{Name: "read_file", Arguments: map[string]interface{}{"path": original, "limit": 13}})
	if err != nil || read.IsError || !strings.Contains(piPlatformReplyText(read), "FULL_ORIGINAL") {
		t.Fatalf("evidence read: %+v %v", read, err)
	}
	reply, err = run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || !reply.IsError || reply.ExecutionID == "" {
		t.Fatalf("per-call budget was reset: %+v %v", reply, err)
	}
	f.server.SetToolAuthorizer(func(context.Context, string, map[string]interface{}) error {
		return errors.New("underlying-policy-denied")
	})
	reply, err = run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || !reply.IsError || !strings.Contains(piPlatformReplyText(reply), "underlying-policy-denied") {
		t.Fatal("underlying authorizer bypassed")
	}
}

func TestPILabPlatformDetachedExecutionsCancelledAndIsolated(t *testing.T) {
	f := newPIPlatformFixture(t)
	started := make(chan string, 4)
	stopped := make(chan string, 4)
	f.server.ConfigureToolWaitTimeoutSeconds(1)
	f.server.RegisterTool(mcp.Tool{Name: "exec", InputSchema: map[string]interface{}{"type": "object"}}, func(ctx context.Context, _ map[string]interface{}) (*mcp.ToolResult, error) {
		id := mcp.MCPExecutionIDFromContext(ctx)
		started <- id
		<-ctx.Done()
		stopped <- id
		return nil, ctx.Err()
	})
	first := f.prepare(t)
	second := f.prepare(t)
	reply, err := first.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || reply.ExecutionID == "" {
		t.Fatal(err)
	}
	id1 := <-started
	other, err := second.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || other.ExecutionID == "" {
		t.Fatal(err)
	}
	id2 := <-started
	if f.platform.agent.tasks.ActiveMCPExecutionID(first.Platform.ConversationID) != id1 {
		t.Fatal("MCP execution missing from task management")
	}
	first.Close()
	first.Close()
	select {
	case id := <-stopped:
		if id != id1 {
			t.Fatal("cancelled another run")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("detached worker leaked")
	}
	if f.platform.agent.tasks.GetTask(first.Platform.ConversationID) != nil || f.platform.agent.tasks.GetTask(second.Platform.ConversationID) == nil {
		t.Fatal("task cleanup crossed run boundary")
	}
	select {
	case id := <-stopped:
		t.Fatalf("other run stopped: %s", id)
	default:
	}
	if _, err = second.Execute(context.Background(), pilab.ToolCall{Name: "exec", Arguments: map[string]interface{}{"execution_id": id1}}); !errors.Is(err, pilab.ErrForbidden) {
		t.Fatalf("foreign execution admitted: %v", err)
	}
	if _, err = f.platform.agent.tasks.CancelTask(second.Platform.ConversationID, ErrTaskCancelled); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-stopped:
		if id != id2 {
			t.Fatal(id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("task-manager cancellation did not stop PI worker")
	}
	second.Close()
}

func TestPILabPlatformSkillAndWorkspaceBoundaries(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	call := func(name string, args map[string]interface{}, wantError bool) string {
		t.Helper()
		reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: name, Arguments: args})
		if err != nil || reply.IsError != wantError {
			t.Fatalf("%s %+v: %+v %v", name, args, reply, err)
		}
		return piPlatformReplyText(reply)
	}
	if !strings.Contains(call("load_skill", map[string]interface{}{"name": "pentest-agent-os"}, false), "SKILL_BODY_ONLY") {
		t.Fatal("skill not loaded")
	}
	if call("read_skill_file", map[string]interface{}{"name": "pentest-agent-os", "path": "references/fixture.md"}, false) != "REFERENCED_SKILL_TEXT" {
		t.Fatal("reference not loaded")
	}
	for _, name := range []string{"../pentest-agent-os", "pentest-agent-os/../x", "C:\\private", "missing"} {
		call("load_skill", map[string]interface{}{"name": name}, true)
	}
	for _, path := range []string{"../outside", "references/../../private", "/etc/passwd", "C:/private", "references\\fixture.md"} {
		call("read_skill_file", map[string]interface{}{"name": "pentest-agent-os", "path": path}, true)
	}
	call("write_file", map[string]interface{}{"path": "notes/result.txt", "content": "abcdef"}, false)
	if text := call("read_file", map[string]interface{}{"path": "notes/result.txt", "offset": 2, "limit": 2}, false); text != "cd" {
		t.Fatal(text)
	}
	if !strings.Contains(call("list_files", map[string]interface{}{"path": "notes"}, false), "result.txt") {
		t.Fatal("missing workspace file")
	}
	call("read_file", map[string]interface{}{"path": "../pi.db"}, true)
	call("read_file", map[string]interface{}{"path": filepath.Join(filepath.Dir(f.cfg.SkillsDir), "pi.db")}, true)
	call("write_file", map[string]interface{}{"path": filepath.Join(f.cfg.SkillsDir, "pentest-agent-os", "SKILL.md"), "content": "overwrite"}, true)
	policy := workspaceguard.FromContext(run.Context)
	piPlatformWriteFixture(t, filepath.Join(policy.EvidenceRoot, "evidence.txt"), "READONLY_ORIGINAL")
	call("write_file", map[string]interface{}{"path": filepath.Join(policy.EvidenceRoot, "evidence.txt"), "content": "overwrite"}, true)
	piPlatformWriteFixture(t, filepath.Join(f.cfg.SkillsDir, ".eino", "private"), "PRIVATE")
	call("read_file", map[string]interface{}{"path": filepath.Join(f.cfg.SkillsDir, ".eino", "private")}, true)
}

func TestPILabPlatformSymlinksDenied(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	private := filepath.Join(t.TempDir(), "private.txt")
	piPlatformWriteFixture(t, private, "PRIVATE_SENTINEL")
	link := filepath.Join(run.Platform.Workspace, "link.txt")
	if err := os.Symlink(private, link); err != nil {
		t.Skipf("本机不允许创建符号链接: %v", err)
	}
	for _, name := range []string{"read_file", "write_file"} {
		reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: name, Arguments: map[string]interface{}{"path": link, "content": "overwrite"}})
		if err != nil || !reply.IsError || strings.Contains(piPlatformReplyText(reply), "PRIVATE_SENTINEL") {
			t.Fatalf("symlink escaped: %+v %v", reply, err)
		}
	}
	skillLink := filepath.Join(f.cfg.SkillsDir, "pentest-agent-os", "references", "link.md")
	if err := os.Symlink(private, skillLink); err != nil {
		t.Fatal(err)
	}
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "read_skill_file", Arguments: map[string]interface{}{"name": "pentest-agent-os", "path": "references/link.md"}})
	if err != nil || !reply.IsError {
		t.Fatal("skill symlink escaped", err)
	}
	data, _ := os.ReadFile(private)
	if string(data) != "PRIVATE_SENTINEL" {
		t.Fatal("outside file changed")
	}
}

func TestPILabPlatformFinishPersistsPartialNotInventedSuccess(t *testing.T) {
	for _, status := range []string{"completed", "cancelled", "failed", "partial"} {
		t.Run(status, func(t *testing.T) {
			f := newPIPlatformFixture(t)
			run := f.prepare(t)
			reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
			if err != nil {
				t.Fatal(err)
			}
			result := &pilab.Run{Status: status, Report: "# 完整报告\n\n声称已完成所有覆盖并且目标完全安全。", ExecutionIDs: []string{"untrusted-node-id"}}
			if err = run.Finish(result); err != nil {
				t.Fatal(err)
			}
			if status == "completed" && result.Status != "partial" {
				t.Fatalf("unverified completion: %+v", result)
			}
			if status != "completed" && result.Status != status {
				t.Fatal("terminal status promoted")
			}
			if !strings.Contains(result.Report, "阶段报告（评估未完成）") || strings.Contains(result.Report, "目标完全安全。") {
				t.Fatal("candidate promoted into phase report")
			}
			if len(result.ExecutionIDs) != 1 || result.ExecutionIDs[0] != reply.ExecutionID {
				t.Fatal("trusted execution ids lost")
			}
			messages, err := f.db.GetMessages(run.Platform.ConversationID)
			if err != nil || len(messages) != 2 {
				t.Fatalf("report persistence: %+v %v", messages, err)
			}
			assistantID := ""
			for _, message := range messages {
				if message.Role == "assistant" && message.Content == result.Report {
					assistantID = message.ID
				}
			}
			if assistantID == "" {
				t.Fatal("assistant report was not persisted")
			}
			assessment, err := f.db.LatestAssessmentRun(run.Platform.ConversationID)
			if err != nil || assessment == nil || assessment.Status == "completed" || assessment.Status == "running" {
				t.Fatalf("assessment promoted: %+v %v", assessment, err)
			}
			if f.platform.agent.tasks.GetTask(run.Platform.ConversationID) != nil {
				t.Fatal("task not finished")
			}
			run.Close()
			again, _ := f.db.GetMessages(run.Platform.ConversationID)
			for _, message := range again {
				if message.ID == assistantID && message.Content != result.Report {
					t.Fatal("Close overwrote finished report")
				}
			}
		})
	}
}

func TestPILabPlatformSkillReadsAreNotExecutionEvidence(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "load_skill", Arguments: map[string]interface{}{"name": "pentest-agent-os"}})
	if err != nil || reply.IsError || reply.ExecutionID == "" {
		t.Fatal("skill read not monitored", err)
	}
	record, err := f.db.GetToolExecution(reply.ExecutionID)
	if err != nil || record.ToolName != "load_skill" || record.ConversationID != run.Platform.ConversationID {
		t.Fatal("skill monitor binding missing", err)
	}
	result := &pilab.Run{Status: "completed", Report: "# 测试报告\n\n读取技能后声称完成测试。"}
	if err = run.Finish(result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial" || result.Error != "missing_execution_evidence" {
		t.Fatalf("skill text became test evidence: %+v", result)
	}
}

func TestPILabPlatformMissingRoleToolsCannotBecomeUtilityOnlyRun(t *testing.T) {
	f := newPIPlatformFixture(t)
	f.platform.config.mu.Lock()
	role := f.cfg.Roles[piPlatformRole]
	role.Tools = []string{"missing-tool"}
	f.cfg.Roles[piPlatformRole] = role
	f.platform.config.mu.Unlock()
	c, _ := f.ginContext()
	if _, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), f.request()); !errors.Is(err, pilab.ErrPlatformUnavailable) {
		t.Fatalf("missing MCP configuration fell back to shared utilities: %v", err)
	}
}

func TestPILabPlatformFinishRejectsReboundConversation(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	other, err := f.db.CreateProject(&database.Project{Name: "PRIVATE_OTHER_PROJECT", ScopeJSON: `{"targets":["PRIVATE_OTHER_SCOPE"]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.db.SetConversationProjectID(run.Platform.ConversationID, other.ID); err != nil {
		t.Fatal(err)
	}
	result := &pilab.Run{Status: "completed", Report: "不应晋升的候选报告。"}
	if err = run.Finish(result); !errors.Is(err, pilab.ErrForbidden) {
		t.Fatalf("rebound conversation delivered: %v", err)
	}
	if strings.Contains(result.Report, "PRIVATE_OTHER") {
		t.Fatal("foreign project leaked into phase report")
	}
	run.Close()
	messages, err := f.db.GetMessages(run.Platform.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if message.Role == "assistant" && message.Content != "PI 正式任务准备中，尚未形成结论。" {
			t.Fatal("rebound conversation was overwritten")
		}
	}
	if f.platform.agent.tasks.GetTask(run.Platform.ConversationID) != nil {
		t.Fatal("rebound task not cleaned up")
	}
}

func TestPILabPlatformStartStorageFailureCleansTask(t *testing.T) {
	f := newPIPlatformFixture(t)
	c, _ := f.ginContext()
	run, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec("DROP TABLE assessment_runs"); err != nil {
		t.Fatal(err)
	}
	if err = run.Start(context.Background(), func() {}); !errors.Is(err, pilab.ErrStorage) {
		t.Fatalf("failed assessment storage accepted: %v", err)
	}
	run.Close()
	run.Close()
	if f.platform.agent.tasks.GetTask(run.Platform.ConversationID) != nil {
		t.Fatal("Start failure leaked task")
	}
}

func TestPILabPlatformFinishCancelsPendingExecution(t *testing.T) {
	f := newPIPlatformFixture(t)
	stopped := make(chan struct{})
	f.server.ConfigureToolWaitTimeoutSeconds(1)
	f.server.RegisterTool(mcp.Tool{Name: "exec", InputSchema: map[string]interface{}{"type": "object"}}, func(ctx context.Context, _ map[string]interface{}) (*mcp.ToolResult, error) {
		<-ctx.Done()
		close(stopped)
		return nil, ctx.Err()
	})
	run := f.prepare(t)
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || reply.ExecutionID == "" {
		t.Fatal(err)
	}
	result := &pilab.Run{Status: "completed", Report: "这是未经核实的完整测试报告。"}
	if err = run.Finish(result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial" || result.Error != "pending_tool_executions" {
		t.Fatalf("pending execution finalized: %+v", result)
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Finish leaked detached execution")
	}
}

func TestPILabPlatformLateRegistryCancellationAndCloseBeforeStart(t *testing.T) {
	f := newPIPlatformFixture(t)
	c, _ := f.ginContext()
	run, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	run.Close()
	run.Close()
	if err = run.Start(context.Background(), func() {}); err == nil {
		t.Fatal("closed preparation restarted")
	}
	reg := mcp.ToolRunRegistryFromContext(run.Context)
	id := uuid.NewString()
	var cancelled atomic.Int32
	f.server.RegisterToolExecutionCancel(id, func() { cancelled.Add(1) })
	reg.RegisterRunningTool(run.Platform.ConversationID, id)
	if cancelled.Load() != 1 {
		t.Fatal("late registered detached execution leaked")
	}
	reg.RegisterRunningTool("other-conversation", uuid.NewString())
}

func TestPILabPlatformToolCallBudgetConcurrent(t *testing.T) {
	f := newPIPlatformFixture(t)
	c, _ := f.ginContext()
	req := f.request()
	req.MaxToolCalls = 3
	run, err := f.platform.Preparer(c)(context.Background(), uuid.NewString(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	ctx, cancel := context.WithCancel(run.Context)
	defer cancel()
	if err = run.Start(ctx, cancel); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "load_skill", Arguments: map[string]interface{}{"name": "pentest-agent-os"}})
			if err == nil && !reply.IsError {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 3 {
		t.Fatal(fmt.Sprintf("budget admitted %d", success.Load()))
	}
}
