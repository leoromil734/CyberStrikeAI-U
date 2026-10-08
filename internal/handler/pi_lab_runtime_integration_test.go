package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/workspaceguard"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// This test loads the actual repository role, skills and registered scanner
// schemas, but deliberately never invokes a scanner or a model endpoint.
func TestPILabRepositoryRoleCatalogCompilesInPI(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, "runtimes", "pi-lab", "node_modules", "typebox", "package.json")); os.IsNotExist(err) {
		t.Skip("optional PI dependencies unavailable")
	}
	f := newPIPlatformFixture(t)
	var role config.RoleConfig
	data, err := os.ReadFile(filepath.Join(repo, "roles", "渗透测试.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = yaml.Unmarshal(data, &role); err != nil {
		t.Fatal(err)
	}
	tools, err := config.LoadToolsFromDir(filepath.Join(repo, "tools"))
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Roles[piPlatformRole] = role
	f.cfg.SkillsDir = filepath.Join(repo, "skills")
	f.cfg.Security.Tools = tools
	security.NewExecutor(&f.cfg.Security, f.server, zap.NewNop()).RegisterTools(f.server)
	prepared := f.prepare(t)
	prepared.Platform.Bridge = &pilab.BridgeConfig{URL: "http://127.0.0.1:10000/tools/call", Token: strings.Repeat("a", 64)}
	input := pilab.Input{RunID: "fixture-catalog", Mode: pilab.ModePlatform, Prompt: "Only compile the repository tool catalog, never execute it.", Scope: []string{"fixture.invalid"}, Limits: pilab.DefaultPlatformLimits, Model: pilab.NormalizeModel(pilab.Model{Provider: "openai", ID: "fixture", APIKey: "fixture-only"}), Platform: prepared.Platform}
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 1024*1024 {
		t.Fatalf("actual role/skill/tool snapshot exceeds stdin bound: %d", len(payload))
	}
	moduleURL := func(name string) string {
		p := filepath.ToSlash(filepath.Join(repo, "runtimes", "pi-lab", "lib", name))
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return (&url.URL{Scheme: "file", Path: p}).String()
	}
	script := fmt.Sprintf("import {validateInput,createRedactor} from %q; import {compilePlatformTools} from %q; let raw='';for await(const chunk of process.stdin)raw+=chunk;const config=validateInput(JSON.parse(raw)); const tools=compilePlatformTools(config.platform.tools,createRedactor()); console.log(JSON.stringify({tools:tools.length,skills:config.platform.skills.length}));", moduleURL("protocol.mjs"), moduleURL("platform.mjs"))
	cmd := exec.Command(node, "--input-type=module", "-e", script)
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual catalog rejected: %v %s", err, out)
	}
	t.Logf("repository snapshot: %d bytes; %s", len(payload), out)
}

// The actual PI SDK calls the Go bridge, existing skill/file tools and the MCP
// execution store. Both the model and operational tool are local test fixtures;
// no real model account, shell process or assessment target is used.
func TestPILabRealSDKPlatformIntegration(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	runtimeDir, err := filepath.Abs(filepath.Join("..", "..", "runtimes", "pi-lab"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDir, "node_modules", "@earendil-works", "pi-coding-agent", "package.json")); os.IsNotExist(err) {
		t.Skip("optional PI dependencies unavailable")
	}
	f := newPIPlatformFixture(t)
	var executed atomic.Int32
	f.server.RegisterTool(mcp.Tool{Name: "exec", Description: "Offline fixture: no process or network execution", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"input": map[string]interface{}{"type": "string"}}, "required": []string{"input"}, "additionalProperties": false}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok || principal.UserID != f.session.UserID || mcp.MCPProjectIDFromContext(ctx) != f.project.ID || mcp.MCPConversationIDFromContext(ctx) == "" {
			t.Error("platform execution lost identity")
		}
		policy := workspaceguard.FromContext(ctx)
		if policy == nil {
			t.Error("workspace policy missing")
			return nil, fmt.Errorf("missing fixture policy")
		}
		data, err := os.ReadFile(filepath.Join(policy.Workspace, "pi-fixture.txt"))
		if err != nil || string(data) != "offline evidence" {
			t.Error("file bridge did not share the platform workspace", err)
		}
		executed.Add(1)
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "offline command fixture; not vulnerability proof"}}}, nil
	})
	var modelCalls atomic.Int32
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls.Add(1)
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content any    `json:"content"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name       string                 `json:"name"`
					Parameters map[string]interface{} `json:"parameters"`
				} `json:"function"`
			} `json:"tools"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid fixture request", 400)
			return
		}
		coordinator := false
		for _, tool := range body.Tools {
			coordinator = coordinator || tool.Function.Name == "delegate_agents"
			if required, exists := tool.Function.Parameters["required"]; exists {
				if _, ok := required.([]interface{}); !ok {
					t.Errorf("invalid provider JSON Schema required for %s", tool.Function.Name)
					http.Error(w, "required must be an array", 400)
					return
				}
			}
		}
		prior := 0
		for _, message := range body.Messages {
			if message.Role == "tool" {
				prior++
			}
		}
		var tool string
		var arguments any
		if coordinator {
			switch prior {
			case 0:
				tool = "load_skill"
				arguments = map[string]interface{}{"name": "pentest-agent-os"}
			case 1:
				tool = "delegate_agents"
				arguments = map[string]interface{}{"tasks": []any{map[string]string{"name": "fixture-worker", "task": "Only run the offline fixture work. Load the base skill, save pi-fixture.txt, then call the fixture exec tool."}}}
			}
		} else {
			switch prior {
			case 0:
				tool = "load_skill"
				arguments = map[string]interface{}{"name": "pentest-agent-os"}
			case 1:
				tool = "write_file"
				arguments = map[string]interface{}{"path": "pi-fixture.txt", "content": "offline evidence"}
			case 2:
				tool = "exec"
				arguments = map[string]interface{}{"input": "fixture"}
			}
		}
		finish := "stop"
		delta := map[string]interface{}{"role": "assistant", "content": "离线夹具运行完成；没有真实目标检测或已验证漏洞，覆盖账本仍有缺口。"}
		if tool != "" {
			finish = "tool_calls"
			args, _ := json.Marshal(arguments)
			delta = map[string]interface{}{"role": "assistant", "tool_calls": []any{map[string]interface{}{"index": 0, "id": fmt.Sprintf("call_%d", modelCalls.Load()), "type": "function", "function": map[string]interface{}{"name": tool, "arguments": string(args)}}}}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, part := range []map[string]interface{}{{"id": "fixture", "object": "chat.completion.chunk", "created": 1, "model": "fixture-model", "choices": []any{map[string]interface{}{"index": 0, "delta": delta, "finish_reason": nil}}}, {"id": "fixture", "object": "chat.completion.chunk", "created": 1, "model": "fixture-model", "choices": []any{map[string]interface{}{"index": 0, "delta": map[string]interface{}{}, "finish_reason": finish}}}} {
			data, _ := json.Marshal(part)
			fmt.Fprintf(w, "data: %s\n\n", data)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer modelServer.Close()
	manager := pilab.New(pilab.Options{Enabled: true, Root: t.TempDir(), Runtime: &pilab.ProcessRuntime{Node: node, Script: filepath.Join(runtimeDir, "runner.mjs")}})
	defer manager.Close()
	ctx, _ := f.ginContext()
	req := f.request()
	req.Title = "Real PI platform fixture"
	req.MaxParallel = 1
	req.MaxAgents = 2
	run, err := manager.CreatePrepared(f.session.UserID, req, pilab.Model{Provider: "openai", BaseURL: modelServer.URL + "/v1", APIKey: "offline-integration-only-key", ID: "fixture-model"}, f.platform.Preparer(ctx))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.After(30 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var final pilab.Run
	for {
		final, err = manager.Get(f.session.UserID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if final.Status != "running" && final.Status != "queued" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("platform fixture timed out")
		case <-ticker.C:
		}
	}
	manager.Close()
	if final.Status != "partial" || len(final.Agents) != 2 || len(final.ExecutionIDs) < 3 || executed.Load() != 1 || len(final.Skills) != 1 {
		page, _ := manager.Events(f.session.UserID, run.ID, 0)
		diagnostic, _ := json.Marshal(page.Events)
		if len(diagnostic) > 10000 {
			diagnostic = diagnostic[:10000]
		}
		t.Fatalf("platform fixture failed: status=%s error=%s agents=%d execs=%d calls=%d skills=%v model=%d events=%s", final.Status, final.Error, len(final.Agents), len(final.ExecutionIDs), executed.Load(), final.Skills, modelCalls.Load(), diagnostic)
	}
	if final.ProjectID != f.project.ID || final.ConversationID == "" || !strings.Contains(final.Report, "\n") {
		t.Fatal("platform delivery was not attached", final)
	}
	messages, err := f.db.GetMessages(final.ConversationID)
	if err != nil || len(messages) < 2 {
		t.Fatal(messages, err)
	}
	if task := f.platform.agent.tasks.GetTask(final.ConversationID); task != nil {
		t.Fatal("completed platform task still active")
	}
}
