package multiagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/cloudwego/eino/adk/middlewares/plantask"
	"github.com/cloudwego/eino/components/tool"
)

func workspaceMiddlewareTools(t *testing.T, ctx context.Context, middleware adk.ChatModelAgentMiddleware) map[string]tool.InvokableTool {
	t.Helper()
	_, agentCtx, err := middleware.BeforeAgent(ctx, &adk.ChatModelAgentContext{})
	if err != nil {
		t.Fatal(err)
	}
	tools := make(map[string]tool.InvokableTool)
	for _, candidate := range agentCtx.Tools {
		info, err := candidate.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if invoke, ok := candidate.(tool.InvokableTool); ok {
			tools[info.Name] = invoke
		}
	}
	return tools
}

func workspaceInvoke(t *testing.T, ctx context.Context, tools map[string]tool.InvokableTool, name string, args map[string]any) (string, error) {
	t.Helper()
	invoke := tools[name]
	if invoke == nil {
		t.Fatalf("missing tool %s", name)
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return invoke.InvokableRun(ctx, string(encoded))
}

func TestWorkspaceFilesystemMiddlewareEnforcesBoundary(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	loc, err := localbk.NewBackend(f.ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	mw, err := subAgentFilesystemMiddleware(f.ctx, loc, nil, "fixture", nil, nil, nil, nil, nil, 0, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := workspaceMiddlewareTools(t, f.ctx, mw)
	outside := filepath.Join(f.platform, "config.yaml")
	writeWorkspaceFixture(t, outside, "canary line 1\ncanary line 2")
	for _, name := range []string{"read_file", "write_file", "edit_file", "ls", "glob", "grep"} {
		args := map[string]any{"file_path": outside, "path": f.platform, "offset": 2, "limit": 1, "content": "mutated", "old_string": "canary", "new_string": "mutated", "pattern": "canary"}
		if name == "glob" {
			args["pattern"] = "**/*"
		}
		if out, err := workspaceInvoke(t, f.ctx, tools, name, args); err == nil || strings.Contains(out, "canary line") {
			t.Fatalf("%s outside: %q %v", name, out, err)
		}
	}
	if _, err := workspaceInvoke(t, f.ctx, tools, "write_file", map[string]any{"file_path": "result.txt", "content": "own evidence"}); err != nil {
		t.Fatal(err)
	}
	if out, err := workspaceInvoke(t, f.ctx, tools, "read_file", map[string]any{"file_path": "result.txt"}); err != nil || !strings.Contains(out, "own evidence") {
		t.Fatalf("model-facing read: %q %v", out, err)
	}
	if out, err := workspaceInvoke(t, f.ctx, tools, "grep", map[string]any{"pattern": "own evidence", "output_mode": "content"}); err != nil || !strings.Contains(out, "own evidence") {
		t.Fatalf("default model-facing grep: %q %v", out, err)
	}
	if out, err := workspaceInvoke(t, f.ctx, tools, "glob", map[string]any{"pattern": "*.txt"}); err != nil || !strings.Contains(out, "result.txt") {
		t.Fatalf("default model-facing glob: %q %v", out, err)
	}
}

func TestWorkspaceReductionReadToolCannotReadPlatform(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	loc, err := localbk.NewBackend(f.ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	mw, err := reductionReadFileMiddleware(f.ctx, loc)
	if err != nil {
		t.Fatal(err)
	}
	tools := workspaceMiddlewareTools(t, f.ctx, mw)
	own := filepath.Join(f.reduction, "clear", "tooluse_fixture")
	outside := filepath.Join(f.platform, "config.yaml")
	writeWorkspaceFixture(t, own, "persisted evidence")
	writeWorkspaceFixture(t, outside, "canary config")
	if out, err := workspaceInvoke(t, f.ctx, tools, "read_file", map[string]any{"file_path": own}); err != nil || !strings.Contains(out, "persisted evidence") {
		t.Fatalf("read reduction: %q %v", out, err)
	}
	if out, err := workspaceInvoke(t, f.ctx, tools, "read_file", map[string]any{"file_path": outside, "offset": 1, "limit": 1}); err == nil || strings.Contains(out, "canary config") {
		t.Fatalf("read config: %q %v", out, err)
	}
	if _, err := workspaceInvoke(t, context.Background(), tools, "read_file", map[string]any{"file_path": own}); err == nil {
		t.Fatal("tool without policy was allowed")
	}
}

func TestWorkspaceTrustedLocalShellIsDisabled(t *testing.T) {
	ma := &config.MultiAgentConfig{EinoSkills: config.MultiAgentEinoSkillsConfig{Disable: true}, EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{ReductionEnable: true}}
	loc, _, _, _, err := prepareEinoSkills(context.Background(), "", ma, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loc.Execute(context.Background(), &filesystem.ExecuteRequest{Command: "echo should-not-execute"}); err == nil {
		t.Fatal("trusted Local exposed an unrestricted shell")
	}
	if _, err := loc.ExecuteStreaming(context.Background(), &filesystem.ExecuteRequest{Command: "echo should-not-execute"}); err == nil {
		t.Fatal("trusted Local exposed an unrestricted streaming shell")
	}
}

func TestWorkspacePlantaskPersistenceAndMiddlewareWiring(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	config := &config.MultiAgentEinoMiddlewareConfig{PlantaskEnable: true}
	_, handlers, _, err := prependEinoMiddlewares(f.ctx, config, einoMWMain, nil, nil, f.skills, "conv-1", "project-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	var tools map[string]tool.InvokableTool
	for _, handler := range handlers {
		candidate := workspaceMiddlewareTools(t, f.ctx, handler)
		if candidate["TaskCreate"] != nil {
			tools = candidate
		}
	}
	if tools == nil {
		t.Fatal("plantask was silently skipped without skills/local")
	}
	for _, subject := range []string{"first task", "second task"} {
		if _, err := workspaceInvoke(t, f.ctx, tools, "TaskCreate", map[string]any{"subject": subject, "description": "workspace fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := workspaceInvoke(t, f.ctx, tools, "TaskList", map[string]any{}); err != nil || !strings.Contains(out, "first task") || !strings.Contains(out, "second task") {
		t.Fatalf("list after second create: %q %v", out, err)
	}
	baseDir := filepath.Join(f.workspace, ".eino", "plantask", "conv-1")
	if _, err := os.Stat(filepath.Join(baseDir, ".highwatermark")); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(f.skills); err != nil || len(entries) != 0 {
		t.Fatalf("plantask modified shared skills: %+v %v", entries, err)
	}
	backend, path, err := prepareWorkspacePlantask(f.ctx, ".eino/plantask", "conv-1")
	if err != nil || path != baseDir {
		t.Fatalf("prepare plan: %q %v", path, err)
	}
	if err := backend.Delete(f.ctx, &plantask.DeleteRequest{FilePath: filepath.Join(baseDir, "1.json")}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(f.skills, "SKILL.md")
	writeWorkspaceFixture(t, outside, "canary skill")
	if err := backend.Delete(f.ctx, &plantask.DeleteRequest{FilePath: outside}); err == nil {
		t.Fatal("plan delete escaped workspace")
	}
	for _, bad := range []string{"../escape", f.skills, ".eino/../escape"} {
		if _, _, err := prepareWorkspacePlantask(f.ctx, bad, "conv-1"); err == nil {
			t.Fatalf("unsafe plan dir %q accepted", bad)
		}
	}
	if _, _, err := prepareWorkspacePlantask(context.Background(), "", "conv-1"); err == nil {
		t.Fatal("plan without policy allowed")
	}
	if _, path, err := prepareWorkspacePlantask(f.ctx, "custom-tasks", "conv-2"); err != nil || !strings.HasPrefix(path, filepath.Join(f.workspace, ".eino")+string(filepath.Separator)) {
		t.Fatalf("custom plans not in workspace/.eino: %q %v", path, err)
	}
}
