package handler

import (
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func TestLoadHistoryPreservesReductionClearMarker(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "reduction-resume.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("resume", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	trace := `[{"role":"system","content":"system","extra":{"cyberstrike_model_facing_trace_version":1}},{"role":"user","content":"keep original scope"},{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"exec","arguments":"{}"}}],"extra":{"_reduction_mw_processed":true}},{"role":"tool","tool_call_id":"call-1","tool_name":"exec","content":"offloaded result"}]`
	if err := db.SaveAgentTrace(conversation.ID, trace, ""); err != nil {
		t.Fatal(err)
	}
	handler := &AgentHandler{db: db, logger: zap.NewNop()}
	history, err := handler.loadHistoryFromAgentTrace(conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range history {
		if message.Role == "assistant" && len(message.ToolCalls) > 0 {
			found = true
			if !message.ReductionCleared || !message.ModelFacingTrace {
				t.Fatalf("real handler restore dropped the clear-once marker: %+v", message)
			}
		}
	}
	if !found {
		t.Fatal("restored trace lost tool call")
	}
	serialized, err := agent.MessagesToTraceJSON(history)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveAgentTrace(conversation.ID, serialized, ""); err != nil {
		t.Fatal(err)
	}
	history, err = handler.loadHistoryFromAgentTrace(conversation.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range history {
		if message.Role == "assistant" && len(message.ToolCalls) > 0 && !message.ReductionCleared {
			t.Fatal("second persisted restore dropped clear metadata")
		}
	}
}
