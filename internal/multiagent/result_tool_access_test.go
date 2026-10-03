package multiagent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agents"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/einomcp"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/dynamictool/toolsearch"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

var resultToolAccessNames = []string{
	builtin.ToolListResultArtifacts,
	builtin.ToolReadResultArtifact,
	builtin.ToolAssembleResultEvidence,
	builtin.ToolQueryReconInventory,
	builtin.ToolRegisterResultArtifact,
}

type resultToolAccessModel struct {
	tools []*schema.ToolInfo
}

func (m *resultToolAccessModel) Generate(_ context.Context, _ []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	m.tools = model.GetCommonOptions(nil, opts...).Tools
	return schema.AssistantMessage("local fixture", nil), nil
}

func (m *resultToolAccessModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	message, err := m.Generate(ctx, messages, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{message}), nil
}

// Exercise shipped allowlists, not a synthetic list that already includes the
// missing tools. This is entirely offline: no provider, scanner or target calls.
func TestCoverageResultToolsReachModelForShippedRoles(t *testing.T) {
	roles, err := config.LoadRolesFromDir(filepath.Join("..", "..", "roles"))
	if err != nil {
		t.Fatal(err)
	}
	load, err := agents.LoadMarkdownAgentsDir(filepath.Join("..", "..", "agents"))
	if err != nil {
		t.Fatal(err)
	}
	cases := make(map[string][]string)
	for _, name := range []string{"渗透测试", "信息收集", "Web应用扫描", "API安全测试", "Web框架测试", "综合漏洞扫描"} {
		role, ok := roles[name]
		if !ok || len(role.Tools) == 0 {
			t.Fatalf("missing explicit role allowlist: %s", name)
		}
		cases["role/"+name] = role.Tools
	}
	for _, id := range []string{"recon", "intel-collection", "attack-surface-enumeration", "penetration", "vulnerability-triage", "reporting-remediation"} {
		for _, sub := range load.SubAgents {
			if sub.ID == id {
				cases["agent/"+id] = sub.RoleTools
			}
		}
		if len(cases["agent/"+id]) == 0 {
			t.Fatalf("missing explicit agent allowlist: %s", id)
		}
	}
	for name, allowed := range cases {
		t.Run(name, func(t *testing.T) {
			for _, required := range resultToolAccessNames {
				if !slices.Contains(allowed, required) {
					t.Fatalf("coverage requires %s but the role filters it out", required)
				}
			}
			testCoverageResultToolBinding(t, allowed)
		})
	}
}

func testCoverageResultToolBinding(t *testing.T, allowed []string) {
	t.Helper()
	ctx := context.Background()
	server := mcp.NewServer(zap.NewNop())
	calls := 0
	for _, name := range append(slices.Clone(resultToolAccessNames), "exec", "out_of_role_fixture") {
		server.RegisterTool(mcp.Tool{Name: name, Description: "local fixture", InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"execution_id": map[string]interface{}{"type": "string"},
				"grouped":      map[string]interface{}{"type": "boolean"},
			}, "required": []string{"execution_id"},
		}}, func(_ context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			calls++
			if args["execution_id"] != "local-execution" || args["grouped"] != true {
				t.Errorf("unexpected fixture arguments: %#v", args)
			}
			return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: `{"groups":[],"candidate_only":true}`}}}, nil
		})
	}
	ag := agent.NewAgent(&config.OpenAIConfig{Model: "local-fixture"}, &config.AgentConfig{}, server, nil, zap.NewNop(), 5)
	defs := ag.ToolsForRole(allowed)
	holder := &einomcp.ConversationHolder{}
	holder.Set("result-access-fixture")
	tools, err := einomcp.ToolsFromDefinitions(ag, holder, defs, nil, nil, nil, "result-access-fixture")
	if err != nil {
		t.Fatal(err)
	}
	index := injectToolNamesOnlyInstruction(ctx, "local instruction", tools, true)
	for _, name := range resultToolAccessNames {
		if !strings.Contains(index, "- "+name+"\n") {
			t.Fatalf("result tool absent from the model name index: %s", name)
		}
	}
	if strings.Contains(index, "out_of_role_fixture") {
		t.Fatal("role filtering admitted an unrelated registered tool")
	}
	// Custom roles remain restrictive. The fix belongs in shipped declarations,
	// not in an implicit bypass of ToolsForRole for all builtin tools.
	restricted := ag.ToolsForRole([]string{"exec"})
	if len(restricted) != 1 || restricted[0].Function.Name != "exec" {
		t.Fatalf("custom allowlist widened: %+v", restricted)
	}
	static, dynamic, split := splitToolsForToolSearchByNames(tools, mergeAlwaysVisibleToolNames(nil), 1)
	if !split || len(dynamic) != 1 {
		t.Fatalf("expected builtin result tools to remain static, with only exec dynamic: split=%v dynamic=%d", split, len(dynamic))
	}
	searchMW, err := toolsearch.New(ctx, &toolsearch.Config{DynamicTools: dynamic})
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := searchMW.BeforeAgent(ctx, &adk.ChatModelAgentContext{Tools: static})
	if err != nil {
		t.Fatal(err)
	}
	var search, inventory tool.InvokableTool
	var infos []*schema.ToolInfo
	for _, mounted := range run.Tools {
		info, err := mounted.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, info)
		switch info.Name {
		case "tool_search":
			search = mounted.(tool.InvokableTool)
		case builtin.ToolQueryReconInventory:
			inventory = mounted.(tool.InvokableTool)
		}
	}
	if search == nil || inventory == nil {
		t.Fatal("search or inventory invocation handle was not mounted")
	}
	// This exact search returned null in the incident. Once the allowlists are
	// fixed it may still be empty: tool_search only indexes dynamic tools.
	text, err := search.InvokableRun(ctx, `{"regex_pattern":"query_recon|list_result|inventory"}`)
	if err != nil {
		t.Fatal(err)
	}
	var selected struct {
		SelectedTools []string `json:"selectedTools"`
	}
	if err := json.Unmarshal([]byte(text), &selected); err != nil || len(selected.SelectedTools) != 0 {
		t.Fatalf("expected an empty dynamic search for static tools: %s (%v)", text, err)
	}
	capture := &resultToolAccessModel{}
	wrapped, err := searchMW.WrapModel(ctx, capture, &adk.ModelContext{Tools: infos})
	if err != nil {
		t.Fatal(err)
	}
	for _, messages := range [][]*schema.Message{
		{schema.UserMessage(strings.Repeat("long local history\n", 9000)), schema.ToolMessage(text, "search", schema.WithToolName("tool_search"))},
		{schema.UserMessage("compacted history without search results")},
	} {
		if _, err := wrapped.Generate(ctx, messages); err != nil {
			t.Fatal(err)
		}
		for _, name := range resultToolAccessNames {
			found := false
			for _, info := range capture.tools {
				if info.Name == name && info.ParamsOneOf != nil {
					found = true
				}
			}
			if !found {
				t.Fatalf("static result schema disappeared after empty search/compaction: %s", name)
			}
		}
	}
	if calls != 0 {
		t.Fatal("tool discovery unexpectedly invoked a handler")
	}
	if _, err := inventory.InvokableRun(ctx, `{"execution_id":"local-execution","grouped":true}`); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("inventory was not invokable: calls=%d", calls)
	}
}

func TestCoverageResultToolInstructionsDistinguishStaticSearch(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	server.RegisterTool(mcp.Tool{Name: builtin.ToolQueryReconInventory, InputSchema: map[string]interface{}{"type": "object"}}, nil)
	ag := agent.NewAgent(&config.OpenAIConfig{Model: "local-fixture"}, &config.AgentConfig{}, server, nil, zap.NewNop(), 5)
	tools, err := einomcp.ToolsFromDefinitions(ag, &einomcp.ConversationHolder{}, ag.ToolsForRole(nil), nil, nil, nil, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	instruction := injectToolNamesOnlyInstruction(context.Background(), "", tools, true)
	for _, required := range []string{"仅搜索非常驻工具", "不代表常驻工具不可用", "当前 tools 已有完整 schema"} {
		if !strings.Contains(instruction, required) {
			t.Fatalf("missing static-tool guidance: %s", required)
		}
	}
}
