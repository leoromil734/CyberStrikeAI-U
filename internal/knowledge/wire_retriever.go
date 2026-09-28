package knowledge

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/openai"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/flow/retriever/multiquery"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// defaultMultiQueryRewritePrompt 与 Eino multiquery 的内置默认模板一致，仅把查询变量改为格式化占位。
const defaultMultiQueryRewritePrompt = `You are an helpful assistant.
	Your role is to create three different versions of the user query to retrieve relevant documents from store.
    Your goal is to improve the performance of similarity search by generating text from different perspectives based on the user query.
	Only provide the generated queries and separate them by newlines. 
	user query: %s`

// 查询改写模型常把推理过程混在正文里（<think>…</think>、沉思段落）并夹带空行/列表符号，
// 而 Eino multiquery 默认按 "\n" 切分且不做任何过滤：空字符串会被当成一条查询送进向量检索器，
// 触发「查询不能为空」使整次检索直接失败。这里先剥离推理块，再逐行清洗。
var (
	rewriteThinkBlockRe = regexp.MustCompile(`(?is)<(think|thinking|reasoning)>.*?</(think|thinking|reasoning)>`)
	rewriteOpenThinkRe  = regexp.MustCompile(`(?is)<(think|thinking|reasoning)>.*$`)
	rewriteListMarkRe   = regexp.MustCompile(`^\s*(?:[-*•‣·]|\(?\d{1,2}\)?\s*[、)）]|\d{1,2}\.\s+)\s*`)
)

// buildMultiQueryRewritePrompt 组装改写提示词，保持与 Eino 默认模板同义。
func buildMultiQueryRewritePrompt(query string) string {
	return fmt.Sprintf(defaultMultiQueryRewritePrompt, query)
}

// sanitizeRewriteQueries 把改写模型的输出清洗成可用的检索变体。
// 返回值可能为空，调用方需在此情况下回退到原始查询。
func sanitizeRewriteQueries(content string) []string {
	cleaned := rewriteThinkBlockRe.ReplaceAllString(content, "")
	// 未闭合的推理块只可能出现在正文之前，整段丢弃，避免半截思考文本被当成查询。
	cleaned = rewriteOpenThinkRe.ReplaceAllString(cleaned, "")

	seen := make(map[string]struct{})
	out := make([]string, 0, 4)
	for _, raw := range strings.Split(cleaned, "\n") {
		line := strings.TrimSpace(rewriteListMarkRe.ReplaceAllString(raw, ""))
		line = trimWrapping(line)
		if line == "" || !hasQueryRune(line) {
			continue
		}
		// 冒号结尾多是改写模型的自述小标题（如「Three different perspectives:」），不是查询。
		if strings.HasSuffix(line, ":") || strings.HasSuffix(line, "：") {
			continue
		}
		key := strings.ToLower(line)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, line)
	}
	return out
}

// hasQueryRune 过滤 ```、---、** 这类只由符号构成的行。
func hasQueryRune(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// wrapperPairs 是模型常用的「整条查询被包裹」符号对；只有成对出现才剥离。
var wrapperPairs = map[rune]rune{'"': '"', '\'': '\'', '“': '”', '‘': '’', '「': '」'}

// trimWrapping 去掉包裹整条查询的成对引号或反引号，但不碰查询自身结尾的标点
// （例如 --header "X-Forwarded-For: 127.0.0.1" 的结尾引号必须保留）。
func trimWrapping(line string) string {
	line = strings.TrimSpace(strings.Trim(line, "`"))
	runes := []rune(line)
	if len(runes) < 2 {
		return line
	}
	if closing, ok := wrapperPairs[runes[0]]; ok && runes[len(runes)-1] == closing {
		return strings.TrimSpace(string(runes[1 : len(runes)-1]))
	}
	return line
}

// newRewriteHandler 包装改写模型：清洗输出，异常或产出为空时回退原始查询，保证检索不会整体失败。
func newRewriteHandler(logger *zap.Logger, rewriteLLM model.ChatModel) func(ctx context.Context, query string) ([]string, error) {
	return func(ctx context.Context, query string) ([]string, error) {
		q := strings.TrimSpace(query)
		if q == "" {
			return nil, fmt.Errorf("查询不能为空")
		}
		msg, err := rewriteLLM.Generate(ctx, []*schema.Message{schema.UserMessage(buildMultiQueryRewritePrompt(q))})
		if err != nil {
			if logger != nil {
				logger.Warn("知识库查询改写失败，回退原始查询", zap.Error(err))
			}
			return []string{q}, nil
		}
		if msg == nil {
			return []string{q}, nil
		}
		queries := sanitizeRewriteQueries(msg.Content)
		if len(queries) == 0 {
			if logger != nil {
				logger.Warn("知识库查询改写未产出可用变体，回退原始查询", zap.Int("contentLen", len(msg.Content)))
			}
			return []string{q}, nil
		}
		return queries, nil
	}
}

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
		// 用自定义 RewriteHandler 取代 Eino 默认的「按 \n 裸切分」解析：默认解析不剥离推理块、
		// 也不过滤空行，模型一旦输出空行就会产出空查询，整次检索直接失败。
		RewriteHandler: newRewriteHandler(r.logger, rewriteLLM),
		MaxQueriesNum:  r.config.MultiQuery.MaxQueriesEffective(),
		OrigRetriever:  vec,
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
