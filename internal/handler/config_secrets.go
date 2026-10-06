package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"cyberstrike-ai/internal/config"
)

const maskedSecret = "********"

// Match both JSON names and Go field names (MCPConfig has YAML tags only).
func secretConfigKey(key string) bool {
	key = strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(key))
	switch key {
	case "apikey", "password", "secret", "clientsecret", "appsecret", "token", "bottoken", "apptoken", "verifytoken", "encodingaeskey", "authorization", "xapikey", "authheadervalue":
		return true
	}
	return false
}

func configSecretSnapshot(cfg *config.Config) map[string]interface{} {
	return map[string]interface{}{
		"ai": cfg.AI, "openai": cfg.OpenAI, "vision": cfg.Vision,
		"fofa": cfg.FOFA, "zoomeye": cfg.ZoomEye, "quake": cfg.Quake, "shodan": cfg.Shodan,
		"mcp": cfg.MCP, "hitl": cfg.Hitl, "knowledge": cfg.Knowledge, "robots": cfg.Robots,
	}
}

func jsonSecretTree(value interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("配置序列化失败")
	}
	var tree map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber() // Preserve int64 IDs and budgets exactly.
	if err := decoder.Decode(&tree); err != nil {
		return nil, errors.New("配置序列化失败")
	}
	return tree, nil
}

// Only walk configuration sections, never tool JSON schemas/examples or public
// metadata. Channel map keys remain exact identities; names/order are not IDs.
func transformConfigSecrets(tree, previous map[string]interface{}, visit func([]string, string, string) (string, error)) error {
	var walk func(interface{}, interface{}, []string) error
	walk = func(value, old interface{}, path []string) error {
		if list, ok := value.([]interface{}); ok {
			before, _ := old.([]interface{})
			for i, child := range list {
				var stored interface{}
				if i < len(before) {
					stored = before[i]
				}
				// Named extension entries may be reordered. An ambiguous or new
				// identity must not inherit another entry's credential.
				if entry, ok := child.(map[string]interface{}); ok {
					for _, field := range []string{"id", "name"} {
						if id, ok := entry[field].(string); ok && id != "" {
							stored = nil
							matches := 0
							for _, candidate := range before {
								if candidate, ok := candidate.(map[string]interface{}); ok && candidate[field] == id {
									stored = candidate
									matches++
								}
							}
							if matches != 1 {
								stored = nil
							}
							break
						}
					}
				}
				if err := walk(child, stored, append(append([]string(nil), path...), "[]")); err != nil {
					return err
				}
			}
			return nil
		}
		node, ok := value.(map[string]interface{})
		if !ok {
			return nil
		}
		before, _ := old.(map[string]interface{})
		for key, child := range node {
			childPath := append(append([]string(nil), path...), key)
			if text, ok := child.(string); ok && secretConfigKey(key) {
				stored, _ := before[key].(string)
				replacement, err := visit(childPath, text, stored)
				if err != nil {
					return err
				}
				node[key] = replacement
				continue
			}
			if err := walk(child, before[key], childPath); err != nil {
				return err
			}
		}
		return nil
	}
	for _, section := range []string{"ai", "openai", "vision", "fofa", "zoomeye", "quake", "shodan", "mcp", "hitl", "knowledge", "robots"} {
		if err := walk(tree[section], previous[section], []string{section}); err != nil {
			return err
		}
	}
	return nil
}

func maskedConfigResponse(response interface{}) (interface{}, error) {
	tree, err := jsonSecretTree(response)
	if err != nil {
		return nil, err
	}
	err = transformConfigSecrets(tree, nil, func(_ []string, text, _ string) (string, error) {
		if text != "" {
			return maskedSecret, nil
		}
		return text, nil
	})
	return tree, err
}

// Restore only markers, not empty strings. Validation happens on detached data
// before any live configuration is changed, including inherited destinations.
func restoreConfigRequestSecrets(request interface{}, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("服务器配置未加载")
	}
	tree, err := jsonSecretTree(request)
	if err != nil {
		return err
	}
	previous, err := jsonSecretTree(configSecretSnapshot(cfg))
	if err != nil {
		return err
	}
	merged := make(map[string]interface{}, len(previous))
	for k, v := range previous {
		merged[k] = v
	}
	for k, v := range tree {
		if v != nil {
			merged[k] = v
		}
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return errors.New("配置序列化失败")
	}
	var next config.Config
	if err := json.Unmarshal(raw, &next); err != nil {
		return errors.New("配置序列化失败")
	}
	if tree["ai"] != nil {
		next.ApplyDefaultAIChannel()
		// UpdateConfig ignores legacy openai whenever ai is provided. Do not
		// resolve a marker against the old default on a default-channel switch.
		delete(tree, "openai")
	}
	err = transformConfigSecrets(tree, previous, func(path []string, text, stored string) (string, error) {
		if strings.TrimSpace(text) != maskedSecret {
			return text, nil
		}
		if stored == "" || strings.TrimSpace(stored) == maskedSecret {
			return "", errors.New("该字段没有已保存凭据，请填写新的值")
		}
		oldTarget, bound := configCredentialTarget(cfg, path)
		newTarget, _ := configCredentialTarget(&next, path)
		if bound && !sameConfigCredentialTarget(oldTarget, newTarget, path) {
			return "", errors.New("凭据目标已更改，请重新填写凭据后保存")
		}
		return stored, nil
	})
	if err != nil {
		return err
	}
	raw, err = json.Marshal(tree)
	if err != nil {
		return errors.New("配置序列化失败")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(request); err != nil {
		return errors.New("配置序列化失败")
	}
	return nil
}

func effectiveProbeProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" || provider == "openai_compatible" {
		return "openai"
	}
	return provider
}

func effectiveProbeURL(baseURL, provider string) string {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		if effectiveProbeProvider(provider) == "claude" {
			return "https://api.anthropic.com"
		}
		return "https://api.openai.com/v1"
	}
	return baseURL
}

func sameProbeTarget(a, b config.OpenAIConfig) bool {
	if effectiveProbeProvider(a.Provider) != effectiveProbeProvider(b.Provider) {
		return false
	}
	left := effectiveProbeURL(a.BaseURL, a.Provider)
	right := effectiveProbeURL(b.BaseURL, b.Provider)
	// Keep paths, query strings, ports and schemes bound, not just the host.
	for _, target := range []string{left, right} {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return false
		}
	}
	return left == right
}

func embeddingProbeConfig(embedding config.EmbeddingConfig, main config.OpenAIConfig) config.OpenAIConfig {
	out := config.VisionConfig{APIKey: embedding.APIKey, BaseURL: embedding.BaseURL, Provider: embedding.Provider, Model: embedding.Model}.OpenAICfgEffective(main)
	// NewEmbedder always uses the OpenAI-compatible embeddings protocol.
	out.Provider = "openai"
	return out
}

// A scope identifies the credential source, never merely an arbitrary URL to
// search for a matching key. Unknown explicit channel IDs must not fall back.
func storedProbeConfig(cfg *config.Config, channelID, scope string) (config.OpenAIConfig, error) {
	if cfg == nil {
		return config.OpenAIConfig{}, errors.New("服务器配置未加载")
	}
	main := cfg.OpenAI
	if channelID = strings.TrimSpace(channelID); channelID != "" {
		channel, ok := cfg.AI.Channels[channelID]
		if !ok {
			return config.OpenAIConfig{}, errors.New("通道不存在，请选择已保存通道或填写新的 API Key")
		}
		main = channel.ToOpenAIConfig()
	}
	switch scope {
	case "", "openai":
		return main, nil
	case "vision":
		return cfg.ResolveAIVision(channelID).OpenAICfgEffective(main), nil
	case "hitlAudit":
		return cfg.Hitl.AuditModelEffective(main), nil
	case "knowledgeEmbedding":
		return embeddingProbeConfig(cfg.Knowledge.Embedding, main), nil
	default:
		return config.OpenAIConfig{}, errors.New("未知凭据范围")
	}
}

func resolveProbeSecret(cfg *config.Config, key, channelID, provider, baseURL, scope string) (string, error) {
	if strings.TrimSpace(key) != maskedSecret {
		return key, nil
	}
	if strings.TrimSpace(channelID) == "" && scope == "" {
		return "", errors.New("请选择凭据范围或已保存通道")
	}
	stored, err := storedProbeConfig(cfg, channelID, scope)
	if err != nil {
		return "", err
	}
	target := config.OpenAIConfig{Provider: provider, BaseURL: baseURL}
	bound := sameProbeTarget(stored, target)
	if !bound && (scope == "" || scope == "openai") {
		// A form may inherit this channel's key but use an independently
		// configured vision/audit/embedding endpoint. Permit only destinations
		// already bound to the SAME saved key, never arbitrary request URLs.
		for _, fallbackScope := range []string{"vision", "hitlAudit", "knowledgeEmbedding"} {
			fallback, fallbackErr := storedProbeConfig(cfg, channelID, fallbackScope)
			if fallbackErr == nil && fallback.APIKey == stored.APIKey && sameProbeTarget(fallback, target) {
				bound = true
				break
			}
		}
	}
	if !bound {
		return "", errors.New("测试目标与已保存凭据不匹配，请重新填写 API Key")
	}
	if strings.TrimSpace(stored.APIKey) == "" || strings.TrimSpace(stored.APIKey) == maskedSecret {
		return "", errors.New("没有已保存的 API Key，请填写新的值")
	}
	return stored.APIKey, nil
}

func sameConfigCredentialTarget(a, b config.OpenAIConfig, path []string) bool {
	// Non-model services have their own defaults; never treat their empty
	// endpoint as an authorization to send a key to OpenAI's public endpoint.
	if path[0] == "fofa" || path[0] == "zoomeye" || path[0] == "quake" || path[0] == "shodan" || path[0] == "robots" || strings.Join(path, ".") == "knowledge.retrieval.rerank.api_key" {
		return strings.TrimSuffix(strings.TrimSpace(a.BaseURL), "/") == strings.TrimSuffix(strings.TrimSpace(b.BaseURL), "/") && a.Provider == b.Provider
	}
	return effectiveProbeProvider(a.Provider) == effectiveProbeProvider(b.Provider) && effectiveProbeURL(a.BaseURL, a.Provider) == effectiveProbeURL(b.BaseURL, b.Provider)
}

func configCredentialTarget(cfg *config.Config, path []string) (config.OpenAIConfig, bool) {
	key := strings.Join(path, ".")
	switch {
	case strings.HasPrefix(key, "openai."):
		return cfg.OpenAI, true
	case strings.HasPrefix(key, "vision."):
		return cfg.Vision.OpenAICfgEffective(cfg.OpenAI), true
	case strings.HasPrefix(key, "hitl.audit_model."):
		return cfg.Hitl.AuditModelEffective(cfg.OpenAI), true
	case strings.HasPrefix(key, "knowledge.embedding."):
		return embeddingProbeConfig(cfg.Knowledge.Embedding, cfg.OpenAI), true
	case strings.HasPrefix(key, "knowledge.retrieval.rerank."):
		r := cfg.Knowledge.Retrieval.Rerank
		baseURL := strings.TrimSpace(r.BaseURL)
		if baseURL == "" {
			baseURL = strings.TrimSpace(cfg.OpenAI.BaseURL)
		}
		return config.OpenAIConfig{Provider: r.ProviderEffective(baseURL), BaseURL: baseURL}, true
	case strings.HasPrefix(key, "fofa."):
		return config.OpenAIConfig{BaseURL: cfg.FOFA.BaseURL}, true
	case strings.HasPrefix(key, "zoomeye."):
		return config.OpenAIConfig{BaseURL: cfg.ZoomEye.BaseURL}, true
	case strings.HasPrefix(key, "quake."):
		return config.OpenAIConfig{BaseURL: cfg.Quake.BaseURL}, true
	case strings.HasPrefix(key, "shodan."):
		return config.OpenAIConfig{BaseURL: cfg.Shodan.BaseURL}, true
	case strings.HasPrefix(key, "robots.wechat."):
		return config.OpenAIConfig{BaseURL: cfg.Robots.Wechat.BaseURL}, true
	}
	if len(path) >= 4 && path[0] == "ai" && path[1] == "channels" {
		ch := cfg.AI.Channels[path[2]]
		if path[3] == "vision" && ch.Vision != nil {
			return ch.Vision.OpenAICfgEffective(ch.ToOpenAIConfig()), true
		}
		return ch.ToOpenAIConfig(), true
	}
	return config.OpenAIConfig{}, false
}

// A probe must not forward stored credentials through redirects, including
// Anthropic x-api-key headers and same-host/different-path redirects.
func credentialProbeHTTPClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Use a dedicated single-request probe rather than the runtime embedder's
// redirect-following client. Runtime indexing/retrieval configuration is untouched.
func probeEmbedding(ctx context.Context, embedding config.EmbeddingConfig, main config.OpenAIConfig, text string) ([]float64, string, error) {
	effective := embeddingProbeConfig(embedding, main)
	model := strings.TrimSpace(embedding.Model)
	if model == "" {
		model = "text-embedding-3-small"
	}
	if strings.TrimSpace(effective.APIKey) == "" || strings.TrimSpace(effective.APIKey) == maskedSecret {
		return nil, model, errors.New("嵌入 API Key 未配置")
	}
	baseURL := effectiveProbeURL(effective.BaseURL, "openai")
	lower := strings.ToLower(baseURL)
	// Keep the same API-root normalization as knowledge.NewEmbedder.
	if !strings.HasSuffix(lower, "/v1") && !strings.Contains(lower, "/v1/") && !strings.Contains(lower, "/compatible-mode/v1") && !strings.Contains(lower, "/openai/deployments") && !strings.Contains(lower, "/embeddings") {
		baseURL += "/v1"
	}
	body, _ := json.Marshal(map[string]interface{}{"model": model, "input": []string{text}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, model, errors.New("嵌入请求地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(effective.APIKey))
	resp, err := credentialProbeHTTPClient().Do(req)
	if err != nil {
		return nil, model, errors.New("嵌入连接失败，请检查目标地址及服务状态")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, model, fmt.Errorf("嵌入 API 返回 HTTP %d", resp.StatusCode)
	}
	var result struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, model, errors.New("嵌入响应格式无效")
	}
	if len(result.Data) == 0 {
		return nil, model, errors.New("嵌入 API 返回空向量")
	}
	return result.Data[0].Embedding, model, nil
}
