package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func aiChannelsPickerRequest(h *ConfigHandler, permission, method, path string) *httptest.ResponseRecorder {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{
			UserID: "picker-user", Permissions: map[string]bool{permission: true}, Scope: database.RBACScopeOwn,
		})
		c.Next()
	})
	router.Use(security.RBACMiddleware(h.db))
	router.GET("/api/config/ai-channels", h.GetAIChannels)
	router.GET("/api/config/ai-channel-probes", h.GetAIChannelProbes)
	router.POST("/api/config/ai-channels/:id/test", h.TestAIChannel)
	router.GET("/api/config", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestAIChannelsPickerReadsPersistedProbesWithoutCredentialsOrModelCalls(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	var calls atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer gateway.Close()
	channel := config.AIChannelConfig{
		Name: "通道", Model: "shared-model", APIKey: "current-secret", BaseURL: gateway.URL,
		Vision: &config.VisionConfig{APIKey: "vision-secret"},
	}
	channels := map[string]config.AIChannelConfig{"ready": channel, "failed": channel, "rotated": channel, "untested": channel, "legacy-error": channel}
	at := time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)
	ms := int64(0) // A real zero measurement must not disappear.
	for _, id := range []string{"ready", "failed", "rotated", "legacy-error", "deleted"} {
		probe := database.AIChannelProbe{
			ChannelID: id, ChannelName: "old-name", Model: "old-model", Status: "ready", Success: true,
			TTFTMs: &ms, TestedAt: at, ConfigHash: aiChannelProbeHash(channel),
		}
		switch id {
		case "failed":
			probe.Status, probe.Success, probe.TTFTMs = "failed", false, nil
			probe.Error = "上游返回 HTTP 401，请检查模型权限、配额与服务地址"
		case "rotated":
			old := channel
			old.APIKey = "previous-secret"
			probe.ConfigHash = aiChannelProbeHash(old)
		case "legacy-error":
			probe.Status, probe.Success = "failed", false
			probe.Error = "Authorization: Bearer previous-secret; https://user:password@host.invalid?api_key=unknown-secret <script>"
		}
		if err := db.SaveAIChannelProbe(probe); err != nil {
			t.Fatal(err)
		}
	}
	h := &ConfigHandler{db: db, config: &config.Config{AI: config.AIConfig{Channels: channels, DefaultChannel: "ready"}}, logger: zap.NewNop()}
	for _, permission := range []string{"chat:read", "tasks:read", "config:read"} {
		t.Run(permission, func(t *testing.T) {
			w := aiChannelsPickerRequest(h, permission, http.MethodGet, "/api/config/ai-channels")
			if w.Code != http.StatusOK {
				t.Fatalf("picker status %d: %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("picker records must not be cached")
			}
			for _, secret := range []string{"secret", "api_key", "base_url", "vision", "config_hash", "password", "Authorization", gateway.URL, "old-name", "old-model", "deleted"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatalf("unexpected private field/value %q in %s", secret, w.Body.String())
				}
			}
			var result AIChannelsPublicResponse
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.DefaultChannel != "ready" || !result.ProbesAvailable || len(result.Channels) != 5 {
				t.Fatalf("invalid list: %+v", result)
			}
			for id, status := range map[string]string{"ready": "ready", "failed": "failed", "rotated": "stale", "untested": "untested", "legacy-error": "failed"} {
				if result.Channels[id].Probe.Status != status {
					t.Fatalf("%s status: %+v", id, result.Channels[id].Probe)
				}
			}
			ready := result.Channels["ready"].Probe
			if ready.TTFTMs == nil || *ready.TTFTMs != 0 || ready.TestedAt == nil || !ready.TestedAt.Equal(at) {
				t.Fatalf("measurements changed: %+v", ready)
			}
			if result.Channels["failed"].Probe.TTFTMs != nil || !strings.Contains(result.Channels["failed"].Probe.Error, "HTTP 401") {
				t.Fatal("failed measurement or diagnostic lost")
			}
			if result.Channels["untested"].Probe.TestedAt != nil || result.Channels["untested"].Probe.TTFTMs != nil {
				t.Fatal("untested channel has fabricated metrics")
			}
			if !result.Channels["rotated"].Probe.Stale || result.Channels["legacy-error"].Probe.Error != "测试失败，详细信息请在系统设置中查看" {
				t.Fatal("stale detection or error allowlist failed")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("reading picker records contacted the model")
	}
}

func TestAIChannelsPickerDoesNotBroadenAdministrativePermissions(t *testing.T) {
	h := &ConfigHandler{config: &config.Config{}}
	for _, permission := range []string{"chat:read", "tasks:read"} {
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/api/config"},
			{http.MethodGet, "/api/config/ai-channel-probes"},
			{http.MethodPost, "/api/config/ai-channels/demo/test"},
		} {
			w := aiChannelsPickerRequest(h, permission, route.method, route.path)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s incorrectly accessed %s %s: %d", permission, route.method, route.path, w.Code)
			}
		}
	}
	for _, permission := range []string{"", "project:read"} {
		w := aiChannelsPickerRequest(h, permission, http.MethodGet, "/api/config/ai-channels")
		if w.Code != http.StatusForbidden {
			t.Fatalf("unrelated permission %q accessed models: %d", permission, w.Code)
		}
	}
}

func TestAIChannelsPickerPreservesSelectionWhenProbeStorageUnavailable(t *testing.T) {
	cfg := &config.Config{AI: config.AIConfig{DefaultChannel: "a", Channels: map[string]config.AIChannelConfig{"a": {Name: "A", Model: "model"}}}}
	db, _ := setupConversationRBACTest(t)
	if err := db.SaveAIChannelProbe(database.AIChannelProbe{ChannelID: "a", TestedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE ai_channel_probes SET result_json='invalid'`); err != nil {
		t.Fatal(err)
	}
	for _, storage := range []*database.DB{nil, db} {
		h := &ConfigHandler{db: storage, config: cfg, logger: zap.NewNop()}
		w := aiChannelsPickerRequest(h, "tasks:read", http.MethodGet, "/api/config/ai-channels")
		var result AIChannelsPublicResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || result.ProbesAvailable || result.DefaultChannel != "a" || result.Channels["a"].Probe.Status != "unknown" {
			t.Fatalf("storage failure broke selection or fabricated an untested result: %s", w.Body.String())
		}
	}
}

func TestPublicAIChannelProbeDetectsConfigurationChanges(t *testing.T) {
	original := config.AIChannelConfig{Model: "m", APIKey: "key", BaseURL: "https://a.invalid"}
	stored := database.AIChannelProbe{Success: true, ConfigHash: aiChannelProbeHash(original)}
	for _, modify := range []func(*config.AIChannelConfig){
		func(ch *config.AIChannelConfig) { ch.APIKey = "rotated" },
		func(ch *config.AIChannelConfig) { ch.Model = "m2" },
		func(ch *config.AIChannelConfig) { ch.BaseURL = "https://b.invalid" },
		func(ch *config.AIChannelConfig) { ch.MaxCompletionTokens = 1000 },
	} {
		changed := original
		modify(&changed)
		if result := publicAIChannelProbe(changed, stored); result.Status != "stale" || !result.Stale {
			t.Fatalf("configuration change not detected: %+v", result)
		}
	}
}
