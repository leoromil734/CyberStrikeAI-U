package multiagent

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
	fsmw "github.com/cloudwego/eino/adk/middlewares/filesystem"
	"github.com/cloudwego/eino/components/tool"
)

// Drive the official tool JSON schema/formatting without an LLM or a database.
func TestWorkspaceFilesystemEinoToolSchema(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	mw, err := fsmw.New(f.ctx, &fsmw.MiddlewareConfig{Backend: f.backend})
	if err != nil {
		t.Fatal(err)
	}
	_, agentCtx, err := mw.BeforeAgent(f.ctx, &adk.ChatModelAgentContext{})
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]tool.InvokableTool{}
	for _, candidate := range agentCtx.Tools {
		info, err := candidate.Info(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		invoke, ok := candidate.(tool.InvokableTool)
		if !ok {
			t.Fatalf("tool %s is not invokable", info.Name)
		}
		tools[info.Name] = invoke
	}
	if len(tools) != 6 || tools["execute"] != nil {
		t.Fatalf("filesystem mounted unexpected tools: %v", tools)
	}
	invoke := func(name string, args map[string]any) (string, error) {
		data, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		return tools[name].InvokableRun(f.ctx, string(data))
	}
	if _, err := invoke("write_file", map[string]any{"file_path": "site/page.js", "content": "one\nTOKEN value\nthree"}); err != nil {
		t.Fatal(err)
	}
	if out, err := invoke("read_file", map[string]any{"file_path": "site/page.js", "offset": 2, "limit": 1}); err != nil || !strings.Contains(out, "TOKEN value") || strings.Contains(out, "three") {
		t.Fatalf("line pagination: %q %v", out, err)
	}
	if out, err := invoke("glob", map[string]any{"pattern": "**/*.js"}); err != nil || !strings.Contains(out, "page.js") {
		t.Fatalf("default glob: %q %v", out, err)
	}
	for _, mode := range []string{"content", "count", "files_with_matches"} {
		out, err := invoke("grep", map[string]any{"pattern": "TOKEN", "output_mode": mode, "head_limit": 1, "type": "js"})
		if err != nil || !strings.Contains(out, "page.js") {
			t.Fatalf("grep mode %s: %q %v", mode, out, err)
		}
	}
	outside := filepath.Join(f.platform, "config.yaml")
	writeWorkspaceFixture(t, outside, "canary config line\ncanary second line")
	for _, name := range []string{"read_file", "write_file", "edit_file", "ls", "glob", "grep"} {
		args := map[string]any{"file_path": outside, "path": f.platform, "offset": 2, "limit": 1, "content": "modified", "old_string": "canary", "new_string": "modified", "pattern": "canary"}
		if name == "glob" {
			args["pattern"] = "**/*"
		}
		if out, err := invoke(name, args); err == nil || strings.Contains(out, "canary second") {
			t.Fatalf("tool %s escaped: %q %v", name, out, err)
		}
	}
}
