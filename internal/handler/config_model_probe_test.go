package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestAIChannelProbeTTFTAndPersistence(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("wrong key")
		}
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload["stream"] != true || payload["model"] != "test-model" {
			t.Errorf("wrong request: %+v", payload)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(25 * time.Millisecond)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(25 * time.Millisecond)
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer gateway.Close()
	db, _ := setupConversationRBACTest(t)
	ch := config.AIChannelConfig{Name: "通道", Model: "test-model", APIKey: "test-secret", BaseURL: gateway.URL + "/v1"}
	h := &ConfigHandler{db: db, config: &config.Config{AI: config.AIConfig{Channels: map[string]config.AIChannelConfig{"a": ch}}}, logger: zap.NewNop()}
	router := gin.New()
	router.POST("/test/:id", h.TestAIChannel)
	router.GET("/results", h.GetAIChannelProbes)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/test/a", nil))
	if w.Code != 200 {
		t.Fatalf("test returned %d: %s", w.Code, w.Body.String())
	}
	var result database.AIChannelProbe
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.TTFTMs == nil || *result.TTFTMs < 20 || result.LatencyMs < *result.TTFTMs+20 {
		t.Fatalf("not a real TTFT: %+v", result)
	}
	results, err := db.ListAIChannelProbes()
	if err != nil || !results["a"].Success {
		t.Fatalf("not persisted: %+v %v", results, err)
	}
	ch.APIKey = "rotated-secret"
	h.config.AI.Channels["a"] = ch
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/results", nil))
	if !strings.Contains(w.Body.String(), `"stale":true`) || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "config_hash") {
		t.Fatalf("stale/security failure: %s", w.Body.String())
	}
}

func TestAIChannelProbeFailuresHaveNoFakeTTFTOrSecrets(t *testing.T) {
	for _, mode := range []string{"empty", "error", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "error":
					http.Error(w, "echo test-secret", 401)
				case "timeout":
					select {
					case <-r.Context().Done():
					case <-time.After(150 * time.Millisecond):
					}
				default:
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: [DONE]\n\n")
				}
			}))
			defer gateway.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			result := runAIChannelProbe(ctx, "a", config.AIChannelConfig{Model: "test", BaseURL: gateway.URL, APIKey: "test-secret"}, zap.NewNop())
			if result.Success || result.TTFTMs != nil || result.Error == "" || strings.Contains(result.Error, "test-secret") {
				t.Fatalf("incorrect failed probe: %+v", result)
			}
		})
	}
}

func TestModelStatsHandlerAccessAndCacheFilterIsolation(t *testing.T) {
	db, user := setupConversationRBACTest(t)
	for _, id := range []string{"one", "two"} {
		conv, err := db.CreateConversation(id, database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if err = db.SetConversationAIChannel(conv.ID, id, "shared-model", id); err != nil {
			t.Fatal(err)
		}
		v, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: conv.ID, Title: id, Severity: "high"})
		if err != nil {
			t.Fatal(err)
		}
		if id == "one" {
			if err = db.SetResourceOwner("vulnerability", v.ID, user.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := NewVulnerabilityHandler(db, zap.NewNop())
	w := performConversationRequest(user, http.MethodGet, "/api/vulnerabilities/model-stats?group_by=model", nil, h.GetModelStats)
	var stats database.VulnerabilityModelStats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || stats.Total != 1 || len(stats.Groups) != 1 {
		t.Fatalf("access leak: %s", w.Body.String())
	}
	w = performConversationRequest(user, http.MethodGet, "/api/vulnerabilities/model-stats?group_by=invalid", nil, h.GetModelStats)
	if w.Code != 400 {
		t.Fatal("unsupported group_by accepted")
	}
}
