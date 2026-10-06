package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func secretTestConfig() *config.Config {
	cfg := &config.Config{
		AI: config.AIConfig{DefaultChannel: "one", Channels: map[string]config.AIChannelConfig{
			"one": {Name: "First", APIKey: "test-secret-one", BaseURL: "https://models.example/v1", Model: "one", Vision: &config.VisionConfig{APIKey: "test-secret-channel-vision", Model: "vision"}},
			"two": {Name: "Second", APIKey: "test-secret-two", BaseURL: "https://models.example/v1", Model: "two"},
		}},
		Vision:  config.VisionConfig{APIKey: "test-secret-global-vision", BaseURL: "https://vision.example/v1", Model: "vision"},
		MCP:     config.MCPConfig{AuthHeader: "X-Service-Token", AuthHeaderValue: "test-secret-mcp", Port: 8181},
		FOFA:    config.FofaConfig{APIKey: "test-secret-fofa"},
		ZoomEye: config.SpaceSearchConfig{APIKey: "test-secret-zoomeye"},
		Quake:   config.SpaceSearchConfig{APIKey: "test-secret-quake"},
		Shodan:  config.SpaceSearchConfig{APIKey: "test-secret-shodan"},
		Robots: config.RobotsConfig{
			Wechat:   config.RobotWechatConfig{BotToken: "test-secret-wechat", ILinkBotID: "public-bot-id"},
			Wecom:    config.RobotWecomConfig{Token: "test-secret-token", Secret: "test-secret-wecom", EncodingAESKey: "test-secret-aes", AgentID: 9007199254740993},
			Dingtalk: config.RobotDingtalkConfig{ClientSecret: "test-secret-dingtalk", ClientID: "public-client-id"},
			Lark:     config.RobotLarkConfig{AppSecret: "test-secret-lark", VerifyToken: "test-secret-verify"},
			Telegram: config.RobotTelegramConfig{BotToken: "test-secret-telegram"},
			Slack:    config.RobotSlackConfig{BotToken: "test-secret-slack-bot", AppToken: "test-secret-slack-app"},
			Discord:  config.RobotDiscordConfig{BotToken: "test-secret-discord"},
			QQ:       config.RobotQQConfig{ClientSecret: "test-secret-qq"},
		},
	}
	cfg.ApplyDefaultAIChannel()
	cfg.Hitl.AuditModel = config.OpenAIConfig{APIKey: "test-secret-audit", Model: "audit"}
	cfg.Knowledge.Embedding = config.EmbeddingConfig{APIKey: "test-secret-embedding", Model: "embed"}
	cfg.Knowledge.Retrieval.Rerank = config.RerankConfig{APIKey: "test-secret-rerank", BaseURL: "https://rerank.example", Provider: "cohere"}
	return cfg
}

func TestConfigSecretsMaskAndRoundTrip(t *testing.T) {
	cfg := secretTestConfig()
	before, _ := json.Marshal(cfg)
	response := configSecretSnapshot(cfg)
	response["agent"] = map[string]interface{}{"max_iterations": 555, "max_fact_writes_per_run": 73}
	response["c2"] = map[string]interface{}{"enabled": false}
	// A schema property is not a stored credential.
	response["tools"] = []interface{}{map[string]interface{}{"input_schema": map[string]interface{}{"api_key": "public schema example"}}}
	masked, err := maskedConfigResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(masked)
	if strings.Contains(string(raw), "test-secret-") {
		t.Fatal("response leaked a credential")
	}
	if !strings.Contains(string(raw), "9007199254740993") || !strings.Contains(string(raw), "public schema example") || !strings.Contains(string(raw), "X-Service-Token") {
		t.Fatal("public fields/numeric precision changed")
	}
	var request map[string]interface{}
	if err := json.Unmarshal(raw, &request); err != nil { // use jsonSecretTree below to retain int64 precision
		t.Fatal(err)
	}
	request, _ = jsonSecretTree(masked)
	if err := restoreConfigRequestSecrets(&request, cfg); err != nil {
		t.Fatal(err)
	}
	if request["ai"].(map[string]interface{})["channels"].(map[string]interface{})["two"].(map[string]interface{})["api_key"] != cfg.AI.Channels["two"].APIKey {
		t.Fatal("channel key was lost or moved")
	}
	if request["mcp"].(map[string]interface{})["AuthHeaderValue"] != cfg.MCP.AuthHeaderValue {
		t.Fatal("MCP AuthHeaderValue was not restored")
	}
	after, _ := json.Marshal(cfg)
	if string(before) != string(after) {
		t.Fatal("mask/restore mutated live configuration")
	}
}

func TestConfigSecretsSaveIdentityAndTargetBinding(t *testing.T) {
	cfg := secretTestConfig()
	t.Run("default switch and same-URL channels", func(t *testing.T) {
		tree, _ := maskedConfigResponse(configSecretSnapshot(cfg))
		req, _ := jsonSecretTree(tree)
		req["ai"].(map[string]interface{})["default_channel"] = "two"
		if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
			t.Fatal(err)
		}
		channels := req["ai"].(map[string]interface{})["channels"].(map[string]interface{})
		for _, id := range []string{"one", "two"} {
			if channels[id].(map[string]interface{})["api_key"] != cfg.AI.Channels[id].APIKey {
				t.Fatal("default switch moved credentials between channels")
			}
		}
	})
	for _, key := range []string{"", "replacement"} {
		req := map[string]interface{}{"openai": config.OpenAIConfig{APIKey: key, BaseURL: "https://new.example/v1"}}
		if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
			t.Fatal(err)
		}
		if req["openai"].(map[string]interface{})["api_key"] != key {
			t.Fatal("explicit replacement/clear ignored")
		}
	}
	cases := map[string]interface{}{
		"new channel":             map[string]interface{}{"ai": config.AIConfig{Channels: map[string]config.AIChannelConfig{"new": {APIKey: maskedSecret}}}},
		"renamed channel":         map[string]interface{}{"ai": config.AIConfig{Channels: map[string]config.AIChannelConfig{"copy": {Name: "First", APIKey: maskedSecret, BaseURL: cfg.OpenAI.BaseURL}}}},
		"changed endpoint":        map[string]interface{}{"openai": config.OpenAIConfig{APIKey: maskedSecret, BaseURL: "https://attacker.example"}},
		"changed protocol":        map[string]interface{}{"openai": config.OpenAIConfig{APIKey: maskedSecret, BaseURL: cfg.OpenAI.BaseURL, Provider: "claude"}},
		"inherited vision target": map[string]interface{}{"ai": config.AIConfig{DefaultChannel: "one", Channels: map[string]config.AIChannelConfig{"one": {APIKey: "replacement", BaseURL: "https://attacker.example", Vision: &config.VisionConfig{APIKey: maskedSecret}}}}},
		"non-model default URL":   map[string]interface{}{"fofa": config.FofaConfig{APIKey: maskedSecret, BaseURL: "https://api.openai.com/v1"}},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := jsonSecretTree(input)
			before, _ := json.Marshal(req)
			if err := restoreConfigRequestSecrets(&req, cfg); err == nil {
				t.Fatal("unsafe marker accepted")
			}
			after, _ := json.Marshal(req)
			if string(before) != string(after) {
				t.Fatal("failed restore partially modified request")
			}
		})
	}
}

func TestConfigSecretsProbeSourceAndTargetBinding(t *testing.T) {
	cfg := secretTestConfig()
	for _, tc := range []struct{ channel, scope, url, want string }{
		{"one", "openai", cfg.OpenAI.BaseURL, "test-secret-one"},
		{"two", "openai", cfg.OpenAI.BaseURL, "test-secret-two"},
		{"one", "vision", cfg.OpenAI.BaseURL, "test-secret-channel-vision"},
		{"two", "vision", cfg.Vision.BaseURL, "test-secret-global-vision"},
		{"two", "hitlAudit", cfg.OpenAI.BaseURL, "test-secret-audit"},
		{"", "knowledgeEmbedding", cfg.OpenAI.BaseURL, "test-secret-embedding"},
	} {
		key, err := resolveProbeSecret(cfg, maskedSecret, tc.channel, "openai_compatible", tc.url+"/", tc.scope)
		if err != nil || key != tc.want {
			t.Fatalf("scope=%s channel=%s resolution failed: %v", tc.scope, tc.channel, err)
		}
	}
	for _, tc := range []struct{ channel, scope, provider, url string }{
		{"missing", "openai", "openai", cfg.OpenAI.BaseURL},
		{"", "", "openai", cfg.OpenAI.BaseURL},
		{"one", "invalid", "openai", cfg.OpenAI.BaseURL},
		{"one", "openai", "claude", cfg.OpenAI.BaseURL},
		{"one", "openai", "openai", "https://attacker.example/v1"},
		{"one", "openai", "openai", "https://models.example/other"},
		{"one", "vision", "openai", cfg.Vision.BaseURL},
		{"one", "openai", "openai", ""},
		{"", "hitlAudit", "openai", "https://attacker.example/v1"},
	} {
		if _, err := resolveProbeSecret(cfg, maskedSecret, tc.channel, tc.provider, tc.url, tc.scope); err == nil {
			t.Fatalf("unsafe probe accepted: %+v", tc)
		}
	}
	if got, err := resolveProbeSecret(cfg, "new-user-key", "new", "openai", "https://new.example", ""); err != nil || got != "new-user-key" {
		t.Fatal("explicit user credential must remain usable on unsaved targets")
	}
}

func TestConfigSecretsInheritedProbeTargets(t *testing.T) {
	cfg := secretTestConfig()
	ch := cfg.AI.Channels["one"]
	ch.Vision = &config.VisionConfig{BaseURL: "https://saved-vision.example/v1", Model: "vision"}
	cfg.AI.Channels["one"] = ch
	key, err := resolveProbeSecret(cfg, maskedSecret, "one", "openai", ch.Vision.BaseURL, "openai")
	if err != nil || key != ch.APIKey {
		t.Fatalf("saved inherited destination failed: %v", err)
	}
	if _, err := resolveProbeSecret(cfg, maskedSecret, "one", "openai", "https://unsaved.example/v1", "openai"); err == nil {
		t.Fatal("unsaved inherited destination accepted")
	}
	ch.Vision.APIKey = "different-vision-key"
	cfg.AI.Channels["one"] = ch
	if _, err := resolveProbeSecret(cfg, maskedSecret, "one", "openai", ch.Vision.BaseURL, "openai"); err == nil {
		t.Fatal("clearing a scoped key allowed wrong-source reuse")
	}
}

func TestConfigSecretsExtensionArrayIdentity(t *testing.T) {
	cfg := secretTestConfig()
	cfg.OpenAI.Reasoning.ExtraRequestFields = map[string]interface{}{"accounts": []interface{}{
		map[string]interface{}{"name": "first", "token": "test-secret-first-extension"},
		map[string]interface{}{"name": "second", "token": "test-secret-second-extension"},
	}}
	masked, err := maskedConfigResponse(map[string]interface{}{"openai": cfg.OpenAI})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(masked)
	if strings.Contains(string(raw), "test-secret-") {
		t.Fatal("extension array leaked a secret")
	}
	req, _ := jsonSecretTree(masked)
	entries := req["openai"].(map[string]interface{})["reasoning"].(map[string]interface{})["extra_request_fields"].(map[string]interface{})["accounts"].([]interface{})
	entries[0], entries[1] = entries[1], entries[0]
	if err := restoreConfigRequestSecrets(&req, cfg); err != nil {
		t.Fatal(err)
	}
	entries = req["openai"].(map[string]interface{})["reasoning"].(map[string]interface{})["extra_request_fields"].(map[string]interface{})["accounts"].([]interface{})
	if entries[0].(map[string]interface{})["token"] != "test-secret-second-extension" {
		t.Fatal("reordered extension secrets were mismatched")
	}
	req, _ = jsonSecretTree(masked)
	req["openai"].(map[string]interface{})["api_key"] = "explicit-new-key"
	req["openai"].(map[string]interface{})["base_url"] = "https://attacker.example"
	if err := restoreConfigRequestSecrets(&req, cfg); err == nil {
		t.Fatal("nested masked extension secret allowed on a changed endpoint")
	}
}

func TestConfigSecretsMCPSpellingsAndPublicNames(t *testing.T) {
	for _, name := range []string{"api_key", "APIKey", "auth_header_value", "AuthHeaderValue", "token", "bot_token", "password", "encoding_aes_key"} {
		if !secretConfigKey(name) {
			t.Fatalf("secret field %s omitted", name)
		}
	}
	for _, name := range []string{"AuthHeader", "name", "model", "max_total_tokens", "client_id", "ilink_bot_id"} {
		if secretConfigKey(name) {
			t.Fatalf("public field %s masked", name)
		}
	}
}

func TestConfigSecretsEmbeddingProbeAndRedirectSafety(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-embedding-key" || r.URL.Path != "/v1/embeddings" {
			t.Error("embedding probe request mismatch")
		}
		var payload struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload.Model == "redirect" {
			w.Header().Set("Location", target.URL)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if payload.Model == "error" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("test-embedding-key"))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"embedding":[0.1,0.2,0.3]}]}`))
	}))
	defer server.Close()
	cfg := config.EmbeddingConfig{APIKey: "test-embedding-key", BaseURL: server.URL, Model: "embed"}
	vec, model, err := probeEmbedding(context.Background(), cfg, config.OpenAIConfig{}, "test")
	if err != nil || model != "embed" || !reflect.DeepEqual(vec, []float64{0.1, 0.2, 0.3}) {
		t.Fatalf("embedding probe failed: %v", err)
	}
	for _, model := range []string{"redirect", "error"} {
		cfg.Model = model
		_, _, err := probeEmbedding(context.Background(), cfg, config.OpenAIConfig{}, "test")
		if err == nil || strings.Contains(err.Error(), cfg.APIKey) {
			t.Fatal("unsafe upstream error")
		}
	}
	if leaked {
		t.Fatal("probe forwarded a credential via redirect")
	}
}
