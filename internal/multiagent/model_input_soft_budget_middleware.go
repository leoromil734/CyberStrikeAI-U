package multiagent

import (
	"context"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/summarization"
	"go.uber.org/zap"
)

// modelInputSoftBudgetMiddleware is the final guard before a normal model call.
// It drops oldest complete rounds and truncates oversized tool output in the latest
// round, but never fails locally — API context limits are handled by overflow retry.
type modelInputSoftBudgetMiddleware struct {
	adk.BaseChatModelAgentMiddleware
	maxTokens           int
	outputReserveTokens int
	toolMaxBytes        int
	counter             summarization.TokenCounterFunc
	logger              *zap.Logger
	phase               string
}

func newModelInputSoftBudgetMiddleware(
	maxTotalTokens int,
	toolMaxBytes int,
	modelName string,
	logger *zap.Logger,
	phase string,
	outputReserve ...int,
) adk.ChatModelAgentMiddleware {
	if maxTotalTokens <= 0 {
		maxTotalTokens = 120000
	}
	if toolMaxBytes <= 0 {
		toolMaxBytes = 12000
	}
	reserve := 0
	if len(outputReserve) > 0 && outputReserve[0] > 0 {
		reserve = outputReserve[0]
	}
	return &modelInputSoftBudgetMiddleware{
		maxTokens:           maxTotalTokens,
		outputReserveTokens: reserve,
		toolMaxBytes:        toolMaxBytes,
		counter:             einoSummarizationTokenCounter(modelName),
		logger:              logger,
		phase:               phase,
	}
}

func (m *modelInputSoftBudgetMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.ChatModelAgentState,
	mc *adk.ModelContext,
) (context.Context, *adk.ChatModelAgentState, error) {
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}
	// Tool schemas are part of the same request/window. Keep every capability
	// mounted, but reserve its tokens and the configured output allowance before
	// applying the existing history guard; never silently drop tools to fit.
	toolTokens, countErr := countMessagesTokens(ctx, nil, m.counter, mcTools(mc))
	messageBudget := m.maxTokens - m.outputReserveTokens - toolTokens
	if countErr != nil || messageBudget <= 0 {
		if m.logger != nil {
			m.logger.Warn("eino model budget exhausted by tools/output reserve; preserving context for overflow recovery",
				zap.String("phase", m.phase), zap.Int("max_tokens", m.maxTokens),
				zap.Int("tool_tokens_estimated", toolTokens), zap.Int("output_reserve_tokens", m.outputReserveTokens),
				zap.Error(countErr))
		}
		return ctx, state, nil
	}
	compacted, changed := compactMessagesByDroppingRounds(ctx, state.Messages, compactMessagesOpts{
		maxTokens:    messageBudget,
		counter:      m.counter,
		toolMaxBytes: m.toolMaxBytes,
		phase:        m.phase,
		logger:       m.logger,
	})
	if !changed {
		return ctx, state, nil
	}
	out := *state
	out.Messages = compacted
	return ctx, &out, nil
}
