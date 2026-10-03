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

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/dynamictool/toolsearch"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

type roleToolSearchCaptureModel struct {
	tools []*schema.ToolInfo
}

func (m *roleToolSearchCaptureModel) Generate(_ context.Context, _ []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	m.tools = model.GetCommonOptions(nil, opts...).Tools
	return &schema.Message{Role: schema.Assistant, Content: "local fixture"}, nil
}

func (m *roleToolSearchCaptureModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	message, err := m.Generate(ctx, messages, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{message}), nil
}

// Reproduces the real path: Markdown role -> role filtering -> MCP/Eino bridge
// -> dynamic tool search -> model-facing schema. All tool handlers are local
// fixtures; this test never contacts FOFA, a model provider or any target.
func TestPenetrationFOFADiscoverySurvivesLongAndCompactedHistory(t *testing.T) {
	ctx := context.Background()
	load, err := agents.LoadMarkdownAgentsDir(filepath.Join("..", "..", "agents"))
	if err != nil {
		t.Fatal(err)
	}
	var roleTools []string
	for _, sub := range load.SubAgents {
		if sub.ID == "penetration" {
			roleTools = sub.RoleTools
			break
		}
	}
	if len(roleTools) == 0 {
		t.Fatal("penetration role not found")
	}

	server := mcp.NewServer(zap.NewNop())
	fofaCalls := 0
	for _, name := range []string{"fofa_search", "httpx", "nuclei", "out_of_role_fixture"} {
		name := name
		server.RegisterTool(mcp.Tool{Name: name, Description: "local fixture", InputSchema: map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{"query": map[string]interface{}{"type": "string"}}, "required": []string{"query"},
		}}, func(_ context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			if name == "fofa_search" {
				fofaCalls++
				if args["query"] != "local fixture only" {
					t.Errorf("unexpected fixture arguments: %#v", args)
				}
			}
			return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "fixture success"}}}, nil
		})
	}
	ag := agent.NewAgent(&config.OpenAIConfig{Model: "local-fixture"}, &config.AgentConfig{}, server, nil, zap.NewNop(), 5)
	defs := ag.ToolsForRole(roleTools)
	var names []string
	for _, def := range defs {
		names = append(names, def.Function.Name)
	}
	if !slices.Contains(names, "fofa_search") {
		t.Fatalf("registered FOFA was removed by the role allowlist: %v", names)
	}
	if slices.Contains(names, "out_of_role_fixture") {
		t.Fatal("fix widened the role allowlist to unrelated registered tools")
	}

	holder := &einomcp.ConversationHolder{}
	holder.Set("role-fofa-fixture")
	tools, err := einomcp.ToolsFromDefinitions(ag, holder, defs, nil, nil, nil, "penetration")
	if err != nil {
		t.Fatal(err)
	}
	static, dynamic, split := splitToolsForToolSearchByNames(tools, mergeAlwaysVisibleToolNames([]string{"httpx"}), 1)
	if !split {
		t.Fatal("expected production dynamic-tool splitting")
	}
	searchMW, err := toolsearch.New(ctx, &toolsearch.Config{DynamicTools: dynamic})
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := searchMW.BeforeAgent(ctx, &adk.ChatModelAgentContext{Tools: static})
	if err != nil {
		t.Fatal(err)
	}
	var search, fofa tool.InvokableTool
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
		case "fofa_search":
			fofa = mounted.(tool.InvokableTool)
		}
	}
	if search == nil || fofa == nil {
		t.Fatal("search or FOFA invocation handle was not mounted")
	}
	searchFor := func(pattern string) (string, []string) {
		t.Helper()
		args, _ := json.Marshal(map[string]string{"regex_pattern": pattern})
		text, err := search.InvokableRun(ctx, string(args))
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			SelectedTools []string `json:"selectedTools"`
		}
		if err := json.Unmarshal([]byte(text), &result); err != nil {
			t.Fatal(err)
		}
		return text, result.SelectedTools
	}
	capture := &roleToolSearchCaptureModel{}
	wrapped, err := searchMW.WrapModel(ctx, capture, &adk.ModelContext{Tools: infos})
	if err != nil {
		t.Fatal(err)
	}
	hasFOFA := func() bool {
		for _, info := range capture.tools {
			if info.Name == "fofa_search" {
				if info.ParamsOneOf == nil {
					t.Fatal("FOFA name was exposed without its argument schema")
				}
				return true
			}
		}
		return false
	}
	text, selected := searchFor("^fofa_search$")
	if !slices.Contains(selected, "fofa_search") {
		t.Fatalf("FOFA search returned no match: %s", text)
	}
	longHistory := []*schema.Message{
		{Role: schema.User, Content: strings.Repeat("long local context fixture\n", 9000)},
		{Role: schema.Tool, ToolName: "tool_search", ToolCallID: "search-before-compaction", Content: text},
	}
	if _, err := wrapped.Generate(ctx, longHistory); err != nil || !hasFOFA() {
		t.Fatalf("FOFA schema missing with long history: %v", err)
	}

	// Compaction may remove the historical search result. That unloads a dynamic
	// schema, but must not remove the tool from the role's searchable catalog.
	compacted := []*schema.Message{{Role: schema.User, Content: "compacted local fixture"}}
	if _, err := wrapped.Generate(ctx, compacted); err != nil || hasFOFA() {
		t.Fatalf("expected lazy schema loading after compaction: %v", err)
	}
	text, selected = searchFor("fofa")
	if !slices.Contains(selected, "fofa_search") {
		t.Fatal("tool became undiscoverable after compaction")
	}
	compacted = append(compacted, &schema.Message{Role: schema.Tool, ToolName: "tool_search", ToolCallID: "search-after-compaction", Content: text})
	stream, err := wrapped.Stream(ctx, compacted)
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if !hasFOFA() {
		t.Fatal("FOFA schema was not restored after searching again")
	}
	if _, selected = searchFor("out_of_role_fixture"); len(selected) != 0 {
		t.Fatal("dynamic search bypassed role restrictions")
	}
	if fofaCalls != 0 {
		t.Fatal("tool discovery unexpectedly executed a business tool")
	}
	if _, err := fofa.InvokableRun(ctx, `{"query":"local fixture only"}`); err != nil {
		t.Fatal(err)
	}
	if fofaCalls != 1 {
		t.Fatalf("discovered tool was not invokable: calls=%d", fofaCalls)
	}
}
