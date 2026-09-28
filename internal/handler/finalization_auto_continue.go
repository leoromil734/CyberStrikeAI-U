package handler

import (
	"context"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

// finalizationAutoContinueMaxAttempts 缺执行证据时最多自动续跑段数；
// 达到上限仍缺证据才写入 blocked，避免模型「总结代替执行」。
const finalizationAutoContinueMaxAttempts = 2

func shouldAutoContinueAfterFinalization(d agentfinalizer.Decision, attempt int) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	if attempt >= finalizationAutoContinueMaxAttempts {
		return false
	}
	return d.CompletionReason == agentfinalizer.ReasonMissingEvidence
}

// tryAutoContinueAfterFinalization 在判定为「缺执行证据」时基于已有轨迹续跑一段。
// 返回 true 表示调用方应 continue 主循环；此时 curHistory / curFinalMessage 已被改写。
// 注意：续跑只恢复模型已有的可见轨迹，不注入新的 user/system 文案，避免污染上下文。
func (h *AgentHandler) tryAutoContinueAfterFinalization(
	taskCtx context.Context,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if !shouldAutoContinueAfterFinalization(decision, *attempt) || result == nil || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)
	if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
		*curHistory = hist
	} else if h.logger != nil {
		h.logger.Warn("finalization auto-continue could not restore trace",
			zap.String("conversationId", conversationID),
			zap.Error(err))
		return false
	}
	// Agent 无感续跑：不追加新的 user/system 文案，只使用上一段模型可见轨迹继续 Runner。
	*curFinalMessage = ""
	if progressCallback != nil {
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId":      conversationID,
			"source":              "finalizer",
			"attempt":             *attempt,
			"maxAttempts":         finalizationAutoContinueMaxAttempts,
			"status":              decision.Status,
			"completionReason":    decision.CompletionReason,
			"missingChecks":       decision.MissingChecks,
			"pendingExecutionIds": decision.PendingExecutionIDs,
			"contextInjection":    false,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(finalizationAutoContinueBackoff(*attempt)):
		return true
	}
}

func finalizationAutoContinueBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 500 * time.Millisecond
	}
	return time.Duration(attempt) * time.Second
}
