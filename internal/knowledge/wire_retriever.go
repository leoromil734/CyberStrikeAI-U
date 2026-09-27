package knowledge

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/openai"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/flow/retriever/multiquery"
	"go.uber.org/zap"
)

// WireRetrieverPipeline builds Eino MultiQuery + HTTP rerank + post-process pipeline on r.
// Call once after NewRetriever; UpdateConfig re-invokes when wireOpenAI is set.
func WireRetrieverPipeline(ctx context.Context, r *Retriever, openAI *config.OpenAIConfig) error {
	if r == nil {
		return fmt.Errorf("retriever is nil")
	}
	if openAI == nil {
		return fmt.Errorf("openai config is nil")
	}
	if r.config == nil {
		return fmt.Errorf("retrieval config is nil")
	}
	r.wireOpenAI = openAI

	httpClient := openai.NewEinoHTTPClient(openAI, &http.Client{Timeout: 120 * time.Second})
	maxCompletionTokens := openAI.MaxCompletionTokensEffective()
	chatCfg := &einoopenai.ChatModelConfig{
		APIKey:              strings.TrimSpace(openAI.APIKey),
		BaseURL:             strings.TrimSuffix(strings.TrimSpace(openAI.BaseURL), "/"),
		Model:               strings.TrimSpace(openAI.Model),
		HTTPClient:          httpClient,
		MaxCompletionTokens: &maxCompletionTokens,
	}
	if chatCfg.Model == "" {
		chatCfg.Model = "gpt-4o"
	}
	rewriteLLM, err := einoopenai.NewChatModel(ctx, chatCfg)
	if err != nil {
		return fmt.Errorf("multi_query rewrite model: %w", err)
	}

	// 精排可显式关闭：部分端点（如 OpenRouter）只提供 /embeddings，不提供 rerank API，
	// 开启只会让每次检索先发一次注定失败的请求，再回退到融合序。
	if r.config.Rerank.EnabledEffective() {
		reranker, err := NewHTTPReranker(&r.config.Rerank, openAI, r.logger)
		if err != nil {
			return fmt.Errorf("reranker: %w", err)
		}
		r.SetDocumentReranker(reranker)
	} else if r.logger != nil {
		r.logger.Info("知识库精排已按配置关闭，检索直接使用融合序")
	}

	vec := NewVectorEinoRetriever(r)
	mq, err := multiquery.NewRetriever(ctx, &multiquery.Config{
		RewriteLLM:    rewriteLLM,
		MaxQueriesNum: r.config.MultiQuery.MaxQueriesEffective(),
		OrigRetriever: vec,
	})
	if err != nil {
		return fmt.Errorf("multi_query: %w", err)
	}

	r.pipeline = newKnowledgePipelineRetriever(mq, r)
	if r.logger != nil {
		// 精排关闭时不要再打印推断出的 provider/model，否则日志会误导（显示已配置某家 rerank，实际未启用）
		rerankState := "disabled"
		rerankModel := ""
		if r.config.Rerank.EnabledEffective() {
			provider := r.config.Rerank.ProviderEffective(strings.TrimSpace(openAI.BaseURL))
			rerankState = provider
			rerankModel = r.config.Rerank.ModelEffective(provider)
		}
		r.logger.Info("知识库检索流水线已启用",
			zap.String("pipeline", "MultiQuery→Vector→Rerank→PostRetrieve"),
			zap.Int("multi_query_max", r.config.MultiQuery.MaxQueriesEffective()),
			zap.String("rerank", rerankState),
			zap.String("rerank_model", rerankModel),
		)
	}
	return nil
}
