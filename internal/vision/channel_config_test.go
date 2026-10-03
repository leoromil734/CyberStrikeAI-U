package vision

import (
	"context"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func TestChannelVisionUsesExplicitModelAndSelectedCredentials(t *testing.T) {
	observed := make(chan observedVisionRequest, 2)
	gateway := newVisionTestGateway(t, observed)
	defer gateway.Close()
	server := mcp.NewServer(zap.NewNop())
	channelVision := config.VisionConfig{Enabled: true, Model: "channel-vision", TimeoutSeconds: 5}
	RegisterAnalyzeImageTool(server, &config.Config{
		// Global vision is disabled: a channel override still registers the tool.
		AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{"local": {Vision: &channelVision}}},
	}, zap.NewNop())
	ctx := WithSessionConfig(context.Background(), channelVision, config.OpenAIConfig{
		BaseURL: gateway.URL + "/v1", APIKey: "selected-key", Model: "text-only-model",
	})
	result, _, err := server.CallTool(ctx, builtin.ToolAnalyzeImage, map[string]interface{}{"path": writeVisionTestImage(t)})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("channel vision failed: result=%+v err=%v", result, err)
	}
	assertObservedVisionRequest(t, <-observed, "/v1/chat/completions", "selected-key", "channel-vision")

	disabled := WithSessionConfig(context.Background(), config.VisionConfig{}, config.OpenAIConfig{})
	result, _, err = server.CallTool(disabled, builtin.ToolAnalyzeImage, map[string]interface{}{"path": "must-not-read"})
	if err != nil || result == nil || !result.IsError || !strings.Contains(toolResultText(result), "未启用") {
		t.Fatalf("disabled channel must not reuse another vision config: %+v %v", result, err)
	}
	if len(observed) != 0 {
		t.Fatal("disabled channel made an upstream request")
	}
}

func TestConcurrentChannelVisionSnapshotsAndPreprocessing(t *testing.T) {
	observed := make(chan observedVisionRequest, 2)
	gateway := newVisionTestGateway(t, observed)
	defer gateway.Close()
	image := writeVisionTestImage(t)
	server := mcp.NewServer(zap.NewNop())
	RegisterAnalyzeImageTool(server, &config.Config{Vision: config.VisionConfig{Enabled: true, MaxImageBytes: 1}}, zap.NewNop())
	var wg sync.WaitGroup
	for _, model := range []string{"vision-a", "vision-b"} {
		wg.Add(1)
		go func(model string) {
			defer wg.Done()
			visionCfg := config.VisionConfig{Enabled: true, Model: model, APIKey: model + "-key", BaseURL: gateway.URL + "/v1", MaxImageBytes: 1048576, TimeoutSeconds: 5}
			ctx := WithSessionConfig(context.Background(), visionCfg, config.OpenAIConfig{Model: "main-model"})
			visionCfg.Model = "mutated-after-snapshot"
			result, _, err := server.CallTool(ctx, builtin.ToolAnalyzeImage, map[string]interface{}{"path": image})
			if err != nil || result == nil || result.IsError || !strings.Contains(toolResultText(result), model+"-ok") {
				t.Errorf("vision config crossed sessions or startup preprocessing was reused: %+v %v", result, err)
			}
		}(model)
	}
	wg.Wait()
	if len(observed) != 2 {
		t.Fatalf("expected two isolated requests; got %d", len(observed))
	}
	seen := make(map[string]bool)
	for range 2 {
		req := <-observed
		assertObservedVisionRequest(t, req, "/v1/chat/completions", req.model+"-key", req.model)
		seen[req.model] = true
	}
	if !seen["vision-a"] || !seen["vision-b"] {
		t.Fatalf("wrong model snapshots: %+v", seen)
	}
}
