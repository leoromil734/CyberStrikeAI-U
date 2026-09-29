package handler

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/openai"
	"go.uber.org/zap"
)

func TestProgressCallbackPersistsSparseSnapshotsWithoutDuplicatingText(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "sparse.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("sparse", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{logger: zap.NewNop(), db: db}
	cb := h.createProgressCallback(context.Background(), nil, conv.ID, msg.ID, nil)
	var reasoning, reply openai.SSESnapshotStream
	cb("reasoning_chain_stream_start", "", map[string]interface{}{"streamId": "reasoning"})
	cb("reasoning_chain_stream_delta", "思考", reasoning.Delta(map[string]interface{}{"streamId": "reasoning"}, "思考"))
	cb("reasoning_chain_stream_delta", "思考", reasoning.Delta(map[string]interface{}{"streamId": "reasoning"}, "思考思考"))
	cb("reasoning_chain_stream_delta", "", reasoning.Final("思考思考"))
	cb("reasoning_chain_stream_end", "思考思考", map[string]interface{}{"streamId": "reasoning"})
	cb("response_start", "", map[string]interface{}{"streamId": "reply"})
	cb("response_delta", "a", reply.Delta(map[string]interface{}{"streamId": "reply"}, "a"))
	cb("response_delta", "a", reply.Delta(map[string]interface{}{"streamId": "reply"}, "aa"))
	cb("response_delta", "", reply.Final("aa"))
	cb("done", "", nil)
	details, err := db.GetProcessDetails(msg.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]string)
	for _, detail := range details {
		if detail.EventType == "planning" || detail.EventType == "reasoning_chain" {
			if _, exists := found[detail.EventType]; exists {
				t.Fatalf("duplicate persisted event: %s", detail.EventType)
			}
			found[detail.EventType] = detail.Message
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(detail.Data), &data); err != nil {
				t.Fatal(err)
			}
			if data["streamSeq"] != float64(3) {
				t.Fatalf("final sequence lost: %#v", data)
			}
		}
	}
	if found["reasoning_chain"] != "思考思考" || found["planning"] != "aa" {
		t.Fatalf("persisted content=%#v", found)
	}
}
