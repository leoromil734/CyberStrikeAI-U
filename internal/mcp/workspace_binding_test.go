package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

func TestProtocolToolCallBindsExecutionBeforeHandler(t *testing.T) {
	s := NewServer(zap.NewNop())
	var id, conversation string
	s.RegisterTool(Tool{Name: "workspace-fixture"}, func(ctx context.Context, _ map[string]interface{}) (*ToolResult, error) {
		id = MCPExecutionIDFromContext(ctx)
		conversation = MCPConversationIDFromContext(ctx)
		return &ToolResult{Content: []Content{{Type: "text", Text: "fixture"}}}, nil
	})
	params, err := json.Marshal(CallToolRequest{Name: "workspace-fixture", Arguments: map[string]interface{}{"execution_id": "model-must-not-select"}})
	if err != nil {
		t.Fatal(err)
	}
	response := s.handleCallTool(WithMCPConversationID(context.Background(), "fixture-conversation"), &Message{Params: params})
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	if id == "" || id == "model-must-not-select" || conversation != "fixture-conversation" {
		t.Fatalf("unbound execution: id=%q conversation=%q", id, conversation)
	}
	if _, ok := s.GetExecution(id); !ok {
		t.Fatal("handler received an untracked execution id")
	}
}
