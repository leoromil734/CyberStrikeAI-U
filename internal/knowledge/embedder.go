package knowledge

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/config"

	einoembedopenai "github.com/cloudwego/eino-ext/components/embedding/openai"
	"github.com/cloudwego/eino/components/embedding"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Embedder 使用 CloudWeGo Eino 的 OpenAI Embedding 组件，并保留速率限制与重试。
type Embedder struct {
	eino   embedding.Embedder
	config *config.KnowledgeConfig
	logger *zap.Logger

	// 解析后的实际请求目标（含回退后的 baseURL / model）
	resolvedBaseURL string
	resolvedModel   string

	rateLimiter    *rate.Limiter
	rateLimitDelay time.Duration
	maxRetries     int
	retryDelay     time.Duration
	mu             sync.Mutex
}

// NewEmbedder 基于 Eino eino-ext OpenAI Embedder；openAIConfig 用于在知识库未单独配置时回退 API Key / BaseURL。
func NewEmbedder(ctx context.Context, cfg *config.KnowledgeConfig, openAIConfig *config.OpenAIConfig, logger *zap.Logger) (*Embedder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("knowledge config is nil")
	}

	var rateLimiter *rate.Limiter
	var rateLimitDelay time.Duration
	if cfg.Indexing.MaxRPM > 0 {
		rpm := cfg.Indexing.MaxRPM
		rateLimiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(rpm)), rpm)
		if logger != nil {
			logger.Info("知识库索引速率限制已启用", zap.Int("maxRPM", rpm))
		}
	} else if cfg.Indexing.RateLimitDelayMs > 0 {
		rateLimitDelay = time.Duration(cfg.Indexing.RateLimitDelayMs) * time.Millisecond
		if logger != nil {
			logger.Info("知识库索引固定延迟已启用", zap.Duration("delay", rateLimitDelay))
		}
	}

	maxRetries := 3
	retryDelay := 1000 * time.Millisecond
	if cfg.Indexing.MaxRetries > 0 {
		maxRetries = cfg.Indexing.MaxRetries
	}
	if cfg.Indexing.RetryDelayMs > 0 {
		retryDelay = time.Duration(cfg.Indexing.RetryDelayMs) * time.Millisecond
	}

	model := strings.TrimSpace(cfg.Embedding.Model)
	if model == "" {
		// 不要默认成 OpenAI 模型名，避免与百炼/兼容端点混用时静默打错
		model = "text-embedding-3-small"
	}

	// 解析顺序：knowledge.embedding.base_url → openai/主通道 base_url → OpenAI 官方
	baseURL := strings.TrimSpace(cfg.Embedding.BaseURL)
	baseURL = strings.TrimSuffix(baseURL, "/")
	baseSource := "knowledge.embedding.base_url"
	if baseURL == "" && openAIConfig != nil {
		baseURL = strings.TrimSpace(openAIConfig.BaseURL)
		baseURL = strings.TrimSuffix(baseURL, "/")
		if baseURL != "" {
			baseSource = "openai.base_url"
		}
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
		baseSource = "default"
	}
	baseURL = normalizeOpenAICompatibleBaseURL(baseURL)

	apiKey := strings.TrimSpace(cfg.Embedding.APIKey)
	keySource := "knowledge.embedding.api_key"
	if apiKey == "" && openAIConfig != nil {
		apiKey = strings.TrimSpace(openAIConfig.APIKey)
		if apiKey != "" {
			keySource = "openai.api_key"
		}
	}
	if apiKey == "" {
		return nil, fmt.Errorf("embedding API key 未配置（请设置 knowledge.embedding.api_key 或 openai.api_key）")
	}

	// 百炼等兼容端点若仍用 OpenAI 官方模型名，给出明确提示（不阻断，由上游返回错误）
	if logger != nil && strings.Contains(strings.ToLower(baseURL), "dashscope") &&
		strings.HasPrefix(strings.ToLower(model), "text-embedding-3") {
		logger.Warn("嵌入模型可能与 base_url 不匹配：DashScope 通常使用 text-embedding-v3/v4，而非 text-embedding-3-*",
			zap.String("model", model), zap.String("baseURL", baseURL))
	}
	if logger != nil && strings.Contains(strings.ToLower(baseURL), "api.openai.com") &&
		strings.Contains(strings.ToLower(model), "text-embedding-v") {
		logger.Warn("嵌入模型可能与 base_url 不匹配：OpenAI 官方使用 text-embedding-3-*，DashScope 模型名 text-embedding-v* 需配百炼 base_url",
			zap.String("model", model), zap.String("baseURL", baseURL))
	}

	timeout := 120 * time.Second
	if cfg.Indexing.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.Indexing.RequestTimeoutSeconds) * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}

	if logger != nil {
		logger.Info("知识库嵌入客户端已初始化",
			zap.String("model", model),
			zap.String("baseURL", baseURL),
			zap.String("baseURLSource", baseSource),
			zap.String("apiKeySource", keySource),
		)
	}

	inner, err := einoembedopenai.NewEmbedder(ctx, &einoembedopenai.EmbeddingConfig{
		APIKey:     apiKey,
		BaseURL:    baseURL,
		ByAzure:    false,
		Model:      model,
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("eino OpenAI embedder: %w", err)
	}

	return &Embedder{
		eino:            inner,
		config:          cfg,
		logger:          logger,
		resolvedBaseURL: baseURL,
		resolvedModel:   model,
		rateLimiter:     rateLimiter,
		rateLimitDelay:  rateLimitDelay,
		maxRetries:      maxRetries,
		retryDelay:      retryDelay,
	}, nil
}

// normalizeOpenAICompatibleBaseURL 保证 OpenAI 兼容端点带 /v1（避免打到站点 HTML）。
// 已含 /compatible-mode/v1、/v1 或 Azure 风格路径时不改。
func normalizeOpenAICompatibleBaseURL(baseURL string) string {
	u := strings.TrimSpace(baseURL)
	u = strings.TrimSuffix(u, "/")
	if u == "" {
		return u
	}
	low := strings.ToLower(u)
	// 已是 API 根
	if strings.HasSuffix(low, "/v1") || strings.Contains(low, "/v1/") ||
		strings.Contains(low, "/compatible-mode/v1") ||
		strings.Contains(low, "/openai/deployments") {
		return u
	}
	// 常见：只写了 https://dashscope.aliyuncs.com/compatible-mode
	if strings.HasSuffix(low, "/compatible-mode") {
		return u + "/v1"
	}
	// 仅 host 或到 /compatible-mode 以外的根：补 /v1
	// 不处理明显非 OpenAI 路径（含 /embeddings 完整路径）——调用方应给 API root
	if !strings.Contains(low, "/embeddings") {
		return u + "/v1"
	}
	return u
}

// EmbeddingModelName 返回配置的嵌入模型名（用于 tiktoken 分块与向量行元数据）。
func (e *Embedder) EmbeddingModelName() string {
	if e == nil || e.config == nil {
		return ""
	}
	s := strings.TrimSpace(e.config.Embedding.Model)
	if s != "" {
		return s
	}
	return "text-embedding-3-small"
}

func (e *Embedder) waitRateLimiter() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.rateLimiter != nil {
		ctx := context.Background()
		if err := e.rateLimiter.Wait(ctx); err != nil && e.logger != nil {
			e.logger.Warn("速率限制器等待失败", zap.Error(err))
		}
	}
	if e.rateLimitDelay > 0 {
		time.Sleep(e.rateLimitDelay)
	}
}

// EmbedText 单条嵌入（float32，与历史存储格式一致）。
func (e *Embedder) EmbedText(ctx context.Context, text string) ([]float32, error) {
	vecs, err := e.EmbedStrings(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(vecs) != 1 {
		return nil, fmt.Errorf("unexpected embedding count: %d", len(vecs))
	}
	return vecs[0], nil
}

// EmbedStrings 批量嵌入，带重试；实现 [embedding.Embedder]，可供 Eino Indexer 使用。
func (e *Embedder) EmbedStrings(ctx context.Context, texts []string, opts ...embedding.Option) ([][]float32, error) {
	if e == nil || e.eino == nil {
		return nil, fmt.Errorf("embedder not initialized")
	}
	if len(texts) == 0 {
		return nil, nil
	}

	var lastErr error
	for attempt := 0; attempt < e.maxRetries; attempt++ {
		if attempt > 0 {
			wait := e.retryDelay * time.Duration(attempt)
			if e.logger != nil {
				e.logger.Debug("嵌入重试前等待", zap.Int("attempt", attempt+1), zap.Duration("wait", wait))
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		} else {
			e.waitRateLimiter()
		}

		raw, err := e.eino.EmbedStrings(ctx, texts, opts...)
		if err == nil {
			out := make([][]float32, len(raw))
			for i, row := range raw {
				out[i] = make([]float32, len(row))
				for j, v := range row {
					out[i][j] = float32(v)
				}
			}
			return out, nil
		}
		lastErr = annotateEmbedError(err, e)
		if !e.isRetryableError(err) {
			return nil, lastErr
		}
		if e.logger != nil {
			e.logger.Debug("嵌入失败，将重试", zap.Int("attempt", attempt+1), zap.Error(lastErr))
		}
	}
	return nil, fmt.Errorf("达到最大重试次数 (%d): %v", e.maxRetries, lastErr)
}

// annotateEmbedError 把「响应体是 HTML」等常见配置错误转成可操作提示。
func annotateEmbedError(err error, e *Embedder) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	base, model := "", ""
	if e != nil {
		base = e.resolvedBaseURL
		model = e.resolvedModel
		if base == "" && e.config != nil {
			base = strings.TrimSpace(e.config.Embedding.BaseURL)
		}
		if model == "" && e.config != nil {
			model = strings.TrimSpace(e.config.Embedding.Model)
		}
	}
	// encoding/json 遇到 <html>… 时典型报错
	if strings.Contains(msg, "invalid character '<'") ||
		strings.Contains(msg, "invalid character \"<\"") ||
		strings.Contains(strings.ToLower(msg), "text/html") {
		return fmt.Errorf("%w | 嵌入接口返回了 HTML 而非 JSON：请检查 knowledge.embedding.base_url 是否为 OpenAI 兼容 API 根（需含 /v1，百炼示例 https://dashscope.aliyuncs.com/compatible-mode/v1）、model=%q 是否与该端点匹配、api_key 是否有效（实际请求 base_url=%q）",
			err, model, base)
	}
	if strings.Contains(msg, "401") || strings.Contains(msg, "Unauthorized") || strings.Contains(msg, "invalid_api_key") {
		return fmt.Errorf("%w | 嵌入鉴权失败：检查 knowledge.embedding.api_key（或回退的 openai.api_key）", err)
	}
	if strings.Contains(msg, "404") || strings.Contains(msg, "model_not_found") || strings.Contains(msg, "does not exist") {
		return fmt.Errorf("%w | 模型或路径不存在：检查 model 名称与 base_url 是否同一厂商（OpenAI: text-embedding-3-small；百炼: text-embedding-v3/v4）；实际 base_url=%q model=%q", err, base, model)
	}
	return err
}

// EmbedTexts 批量 float32 嵌入（兼容旧调用；单次请求批量以减小延迟）。
func (e *Embedder) EmbedTexts(ctx context.Context, texts []string) ([][]float32, error) {
	return e.EmbedStrings(ctx, texts)
}

func (e *Embedder) isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limit") {
		return true
	}
	if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") ||
		strings.Contains(errStr, "503") || strings.Contains(errStr, "504") {
		return true
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "network") || strings.Contains(errStr, "EOF") {
		return true
	}
	return false
}

// einoFloatEmbedder adapts [][]float32 embedder to Eino's [][]float64 [embedding.Embedder] for Indexer.Store.
type einoFloatEmbedder struct {
	inner *Embedder
}

func (w *einoFloatEmbedder) EmbedStrings(ctx context.Context, texts []string, opts ...embedding.Option) ([][]float64, error) {
	vec32, err := w.inner.EmbedStrings(ctx, texts, opts...)
	if err != nil {
		return nil, err
	}
	out := make([][]float64, len(vec32))
	for i, row := range vec32 {
		out[i] = make([]float64, len(row))
		for j, v := range row {
			out[i][j] = float64(v)
		}
	}
	return out, nil
}

func (w *einoFloatEmbedder) GetType() string {
	return "CyberStrikeKnowledgeEmbedder"
}

func (w *einoFloatEmbedder) IsCallbacksEnabled() bool {
	return false
}

// EinoEmbeddingComponent returns an [embedding.Embedder] that uses the same retry/rate-limit path
// and produces float64 vectors expected by generic Eino indexer helpers.
func (e *Embedder) EinoEmbeddingComponent() embedding.Embedder {
	return &einoFloatEmbedder{inner: e}
}
