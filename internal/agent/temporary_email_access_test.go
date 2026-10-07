package agent

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func TestTemporaryEmailIsSharedWithoutWideningOtherRoleTools(t *testing.T) {
	server := mcp.NewServer(zap.NewNop())
	for _, name := range []string{builtin.ToolTemporaryEmail, "exec", "unrelated_fixture"} {
		server.RegisterTool(mcp.Tool{Name: name, Description: "fixture", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}}, func(context.Context, map[string]interface{}) (*mcp.ToolResult, error) { return &mcp.ToolResult{}, nil })
	}
	ag := NewAgent(&config.OpenAIConfig{Model: "fixture"}, &config.AgentConfig{}, server, nil, zap.NewNop(), 5)
	for _, allowed := range [][]string{{"exec"}, {"missing_role_tool"}, nil} {
		defs := ag.ToolsForRole(allowed)
		found := false
		for _, d := range defs {
			if d.Function.Name == builtin.ToolTemporaryEmail {
				found = true
			}
			if len(allowed) > 0 && d.Function.Name == "unrelated_fixture" {
				t.Fatal("unrelated tools became global")
			}
		}
		if !found {
			t.Fatal("role allowlist hid the shared mailbox utility")
		}
	}
}
