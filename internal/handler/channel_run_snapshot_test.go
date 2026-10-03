package handler

import (
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func TestRunChannelSnapshotIncludesVisionAndStableName(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	cfg := &config.Config{AI: config.AIConfig{DefaultChannel: "a", Channels: map[string]config.AIChannelConfig{
		"a": {Name: "original-name", Model: "model-a", APIKey: "fixture-key", Vision: &config.VisionConfig{Enabled: true, Model: "vision-a"}},
		"b": {Name: "channel-b", Model: "model-b", Vision: &config.VisionConfig{Enabled: false}},
	}}}
	h := &AgentHandler{db: db, config: cfg, logger: zap.NewNop()}
	run, id, err := h.configForAIChannel("a")
	if err != nil || id != "a" || run.Vision.Model != "vision-a" {
		t.Fatalf("bad run snapshot: %+v %s %v", run, id, err)
	}
	cfg.AI.Channels["a"] = config.AIChannelConfig{Name: "renamed", Model: "changed-model"}
	conv, err := db.CreateConversation("run", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h.recordConversationAIChannel(conv.ID, id, run)
	tasks := []*AgentTask{{ConversationID: conv.ID}}
	attachAgentTaskAIModels(db, tasks)
	if tasks[0].AIChannelName != "original-name" || tasks[0].AIModel != "model-a" {
		t.Fatalf("record used mutable config: %+v", tasks[0])
	}
	if _, _, err := h.configForAIChannel("missing"); err == nil {
		t.Fatal("unknown channel incorrectly attributed to a default model")
	}
	cfg.AI.DefaultChannel = "b"
	fallback := h.batchTaskRunConfig("missing")
	if fallback.OpenAI.Model != "model-b" || fallback.AI.DefaultChannel != "b" || fallback.Vision.Enabled {
		t.Fatalf("bad batch fallback: %+v", fallback)
	}
	cfg.AI.Channels["b"] = config.AIChannelConfig{Name: "b", Model: "model-b", Vision: &config.VisionConfig{Enabled: true, Model: "vision-b"}}
	if h.batchTaskRunConfig("").Vision.Model != "vision-b" {
		t.Fatal("default batch task ignored per-channel vision")
	}
}
