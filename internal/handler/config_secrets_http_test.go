package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func performConfigSecretJSON(method string, body interface{}, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/config", bytes.NewReader(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	handler(c)
	return w
}

func TestConfigSecretsHTTPGetSaveDefaultSwitch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := secretTestConfig()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ai: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &ConfigHandler{config: cfg, configPath: path, logger: zap.NewNop()}
	w := performConfigSecretJSON(http.MethodGet, nil, h.GetConfig)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "test-secret-") {
		t.Fatalf("unsafe configuration response: status %d", w.Code)
	}
	var public GetConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	if public.MCP.AuthHeaderValue != maskedSecret || public.AI.Channels["one"].APIKey != maskedSecret || len(public.Tools) != 0 {
		t.Fatal("mask or include_tools behavior regressed")
	}
	public.AI.DefaultChannel = "two"
	w = performConfigSecretJSON(http.MethodPut, UpdateConfigRequest{AI: &public.AI, OpenAI: &public.OpenAI}, h.UpdateConfig)
	if w.Code != http.StatusOK {
		t.Fatalf("masked save: %d %s", w.Code, w.Body.String())
	}
	if cfg.OpenAI.APIKey != "test-secret-two" || cfg.AI.Channels["one"].APIKey != "test-secret-one" {
		t.Fatal("default switch mismatched channel keys")
	}
	saved, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(saved), maskedSecret) || !strings.Contains(string(saved), "test-secret-two") {
		t.Fatal("masked value reached persisted configuration")
	}
}

func TestConfigSecretsHTTPProbesBoundAndErrorsSafe(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer test-secret-one" {
			t.Error("wrong saved key sent")
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Bearer test-secret-one"}`))
	}))
	defer server.Close()
	cfg := secretTestConfig()
	ch := cfg.AI.Channels["one"]
	ch.BaseURL = server.URL
	cfg.AI.Channels["one"] = ch
	cfg.ApplyDefaultAIChannel()
	h := &ConfigHandler{config: cfg, logger: zap.NewNop()}
	for _, handler := range []gin.HandlerFunc{h.TestOpenAI, h.ListModels} {
		w := performConfigSecretJSON(http.MethodPost, TestOpenAIRequest{APIKey: maskedSecret, ChannelID: "one", CredentialScope: "openai", BaseURL: server.URL, Model: "test"}, handler)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "test-secret-") || !strings.Contains(w.Body.String(), "401") {
			t.Fatalf("unsafe probe error: %d %s", w.Code, w.Body.String())
		}
		w = performConfigSecretJSON(http.MethodPost, TestOpenAIRequest{APIKey: maskedSecret, ChannelID: "one", CredentialScope: "openai", BaseURL: server.URL + "/other", Model: "test"}, handler)
		if w.Code != http.StatusBadRequest {
			t.Fatal("changed request path accepted with saved key")
		}
	}
	if calls != 2 {
		t.Fatalf("unexpected network calls: %d", calls)
	}
}

func TestConfigSecretsHTTPVisionUsesChannelCredentialAndFinalTarget(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer test-secret-channel-vision" {
			t.Error("global vision credential used for channel vision")
		}
		_, _ = w.Write([]byte(`{"model":"vision","choices":[{"message":{"content":"OK"}}]}`))
	}))
	defer server.Close()
	cfg := secretTestConfig()
	ch := cfg.AI.Channels["one"]
	ch.BaseURL = server.URL
	cfg.AI.Channels["one"] = ch
	h := &ConfigHandler{config: cfg, logger: zap.NewNop()}
	payload := TestVisionRequest{ChannelID: "one", Vision: config.VisionConfig{APIKey: maskedSecret, Model: "vision"}, OpenAI: config.OpenAIConfig{BaseURL: server.URL, APIKey: maskedSecret}}
	w := performConfigSecretJSON(http.MethodPost, payload, h.TestVision)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) || calls != 1 {
		t.Fatalf("vision probe: %d %s", w.Code, w.Body.String())
	}
	payload.Vision.BaseURL = server.URL + "/attacker"
	w = performConfigSecretJSON(http.MethodPost, payload, h.TestVision)
	if w.Code != http.StatusBadRequest || calls != 1 {
		t.Fatal("final effective vision target was not checked")
	}
	payload.Vision.APIKey = "" // Inherit main key, still cannot change its destination.
	w = performConfigSecretJSON(http.MethodPost, payload, h.TestVision)
	if w.Code != http.StatusBadRequest || calls != 1 {
		t.Fatal("vision fallback leaked the main credential")
	}
}

func TestConfigSecretsHTTPEmbeddingRejectsImplicitKeyExfiltration(t *testing.T) {
	cfg := secretTestConfig()
	h := &ConfigHandler{config: cfg, logger: zap.NewNop()}
	for _, key := range []string{"", maskedSecret} {
		w := performConfigSecretJSON(http.MethodPost, TestEmbeddingRequest{APIKey: key, BaseURL: "https://attacker.example/v1"}, h.TestEmbedding)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "test-secret-") {
			t.Fatal("embedding allowed a custom target with implicit saved key")
		}
	}
}
