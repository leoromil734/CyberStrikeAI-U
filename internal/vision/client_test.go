package vision

import (
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func TestLooksLikeCaptchaQuestion(t *testing.T) {
	if !looksLikeCaptchaQuestion("识别验证码，只输出字符") {
		t.Fatal("expected captcha hint")
	}
	if looksLikeCaptchaQuestion("描述登录页布局") {
		t.Fatal("expected non-captcha")
	}
}

func TestSessionOpenAIConfigContextCopiesValue(t *testing.T) {
	selected := config.OpenAIConfig{
		APIKey:  "session-key",
		BaseURL: "https://session.example/v1",
		Model:   "session-model",
	}
	ctx := WithSessionOpenAIConfig(context.Background(), selected)
	selected.APIKey = "mutated-key"

	got, ok := SessionOpenAIConfigFromContext(ctx)
	if !ok {
		t.Fatal("session OpenAI config missing from context")
	}
	if got.APIKey != "session-key" || got.BaseURL != "https://session.example/v1" || got.Model != "session-model" {
		t.Fatalf("session OpenAI config = %+v", got)
	}
}

func TestAnalyzeDoesNotFallbackMissingSessionIdentityFields(t *testing.T) {
	client := NewClient(config.VisionConfig{
		APIKey:  "startup-vision-key",
		BaseURL: "https://startup-vision.invalid/v1",
		Model:   "startup-vision-model",
	}, config.OpenAIConfig{
		APIKey:  "startup-main-key",
		BaseURL: "https://startup-main.invalid/v1",
		Model:   "startup-main-model",
	})
	imagePayload := ImagePayload{Bytes: []byte{1}, MIMEType: "image/png"}

	t.Run("api key", func(t *testing.T) {
		ctx := WithSessionOpenAIConfig(context.Background(), config.OpenAIConfig{
			BaseURL: "https://session.invalid/v1",
			Model:   "session-model",
		})
		_, err := client.Analyze(ctx, imagePayload, "describe")
		if err == nil || !strings.Contains(err.Error(), "vision API key is empty") {
			t.Fatalf("Analyze error = %v", err)
		}
	})

	t.Run("model", func(t *testing.T) {
		ctx := WithSessionOpenAIConfig(context.Background(), config.OpenAIConfig{
			APIKey:  "session-key",
			BaseURL: "https://session.invalid/v1",
		})
		_, err := client.Analyze(ctx, imagePayload, "describe")
		if err == nil || !strings.Contains(err.Error(), "vision model is empty") {
			t.Fatalf("Analyze error = %v", err)
		}
	})
}

func TestAnalyzeImageToolUsesSessionOpenAIConfigThroughMCP(t *testing.T) {
	imagePath := writeVisionTestImage(t)
	observed := make(chan observedVisionRequest, 1)
	gateway := newVisionTestGateway(t, observed)
	defer gateway.Close()

	server := mcp.NewServer(zap.NewNop())
	RegisterAnalyzeImageTool(server, &config.Config{
		Vision: config.VisionConfig{
			Enabled:        true,
			APIKey:         "startup-vision-key",
			BaseURL:        "https://startup-vision.invalid/v1",
			Model:          "startup-vision-model",
			TimeoutSeconds: 5,
		},
		OpenAI: config.OpenAIConfig{
			APIKey:  "startup-main-key",
			BaseURL: "https://startup-main.invalid/v1",
			Model:   "startup-main-model",
		},
	}, zap.NewNop())

	ctx := WithSessionOpenAIConfig(context.Background(), config.OpenAIConfig{
		Provider: "openai",
		APIKey:   "session-key",
		BaseURL:  gateway.URL + "/v1",
		Model:    "session-model",
	})
	result, _, err := server.CallTool(ctx, builtin.ToolAnalyzeImage, map[string]interface{}{
		"path":     imagePath,
		"question": "描述图片",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("analyze_image result = %#v", result)
	}
	if got := toolResultText(result); !strings.Contains(got, "session-model-ok") {
		t.Fatalf("analyze_image output = %q", got)
	}

	req := <-observed
	assertObservedVisionRequest(t, req, "/v1/chat/completions", "session-key", "session-model")
}

func TestAnalyzeImageToolKeepsConcurrentSessionConfigsIsolated(t *testing.T) {
	imagePath := writeVisionTestImage(t)
	type sessionCase struct {
		key   string
		model string
	}
	sessions := []sessionCase{
		{key: "session-key-a", model: "session-model-a"},
		{key: "session-key-b", model: "session-model-b"},
	}

	server := mcp.NewServer(zap.NewNop())
	RegisterAnalyzeImageTool(server, &config.Config{
		Vision: config.VisionConfig{
			Enabled:        true,
			TimeoutSeconds: 5,
		},
	}, zap.NewNop())

	observed := make(chan observedVisionRequest, len(sessions))
	gateways := make([]*httptest.Server, 0, len(sessions))
	for range sessions {
		gateway := newVisionTestGateway(t, observed)
		gateways = append(gateways, gateway)
		defer gateway.Close()
	}

	errCh := make(chan error, len(sessions))
	var wg sync.WaitGroup
	for i, session := range sessions {
		i, session := i, session
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := WithSessionOpenAIConfig(context.Background(), config.OpenAIConfig{
				Provider: "openai",
				APIKey:   session.key,
				BaseURL:  gateways[i].URL + fmt.Sprintf("/session-%d/v1", i),
				Model:    session.model,
			})
			result, _, err := server.CallTool(ctx, builtin.ToolAnalyzeImage, map[string]interface{}{
				"path": imagePath,
			})
			if err != nil {
				errCh <- err
				return
			}
			if result == nil || result.IsError || !strings.Contains(toolResultText(result), session.model+"-ok") {
				errCh <- fmt.Errorf("session %d result = %#v", i, result)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	seen := make(map[string]observedVisionRequest, len(sessions))
	for range sessions {
		req := <-observed
		seen[req.model] = req
	}
	for i, session := range sessions {
		req, ok := seen[session.model]
		if !ok {
			t.Fatalf("request for model %q not observed: %#v", session.model, seen)
		}
		assertObservedVisionRequest(t, req, fmt.Sprintf("/session-%d/v1/chat/completions", i), session.key, session.model)
	}
}

type observedVisionRequest struct {
	path  string
	auth  string
	model string
	err   error
}

func newVisionTestGateway(t *testing.T, observed chan<- observedVisionRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body struct {
			Model string `json:"model"`
		}
		err := json.NewDecoder(r.Body).Decode(&body)
		observed <- observedVisionRequest{
			path:  r.URL.Path,
			auth:  r.Header.Get("Authorization"),
			model: body.Model,
			err:   err,
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(
			`{"id":"chatcmpl-vision-test","object":"chat.completion","created":1,"model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`,
			body.Model, body.Model+"-ok"))
	}))
}

func assertObservedVisionRequest(t *testing.T, got observedVisionRequest, wantPath, wantKey, wantModel string) {
	t.Helper()
	if got.err != nil {
		t.Fatalf("decode vision request: %v", got.err)
	}
	if got.path != wantPath {
		t.Errorf("request path = %q, want %q", got.path, wantPath)
	}
	if got.auth != "Bearer "+wantKey {
		t.Errorf("Authorization = %q, want Bearer for selected session", got.auth)
	}
	if got.model != wantModel {
		t.Errorf("request model = %q, want %q", got.model, wantModel)
	}
}

func toolResultText(result *mcp.ToolResult) string {
	if result == nil {
		return ""
	}
	var b strings.Builder
	for _, content := range result.Content {
		if content.Type == "text" {
			b.WriteString(content.Text)
		}
	}
	return b.String()
}

func writeVisionTestImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vision-test.png")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	if err := png.Encode(file, img); err != nil {
		_ = file.Close()
		t.Fatalf("encode image: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
	return path
}
