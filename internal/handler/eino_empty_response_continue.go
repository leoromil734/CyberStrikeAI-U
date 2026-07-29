package handler

import (
	"context"
	"fmt"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

// rebindEinoRunningTask 中断并继续 / 空正文续跑：重建 cancel 链与超时 ctx，保持任务 running。
func (h *AgentHandler) rebindEinoRunningTask(parent context.Context, conversationID string, timeoutCancel context.CancelFunc) (context.Context, context.CancelCauseFunc, context.Context, context.CancelFunc) {
	if timeoutCancel != nil {
		timeoutCancel()
	}
	baseCtx, cancelWithCause := context.WithCancelCause(detachedAgentContext(parent))
	h.tasks.BindTaskCancel(conversationID, cancelWithCause)
	taskCtx, newTimeoutCancel := context.WithTimeout(baseCtx, 600*time.Minute)
	h.tasks.UpdateTaskStatus(conversationID, "running")
	return baseCtx, cancelWithCause, taskCtx, newTimeoutCancel
}

// tryContinueOnEinoEmptyResponse Run 成功但缺少可交付正文时退避续跑；true 表示已准备下一段 Run。
func (h *AgentHandler) tryContinueOnEinoEmptyResponse(
	taskCtx context.Context,
	mw *config.MultiAgentEinoMiddlewareConfig,
	conversationID string,
	result *multiagent.RunResult,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	preferFinalReport bool,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	inject, continueKind := multiagent.EinoResponseContinueInstruction(result, preferFinalReport)
	if result == nil || inject == "" || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	maxAttempts := multiagent.EmptyResponseContinueMaxAttemptsFromConfig(mw)
	if *attempt >= maxAttempts {
		if h.logger != nil {
			h.logger.Warn("eino response continue exhausted",
				zap.String("conversationId", conversationID),
				zap.String("continueKind", continueKind),
				zap.Int("maxAttempts", maxAttempts))
		}
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)

	backoff := multiagent.EmptyResponseContinueBackoff(*attempt-1, mw)
	waitReason := "未捕获到助手正文"
	if continueKind == multiagent.EinoResponseContinueKindFinalReport {
		waitReason = "只返回了阶段状态，缺少正式报告"
	}
	waitMsg := fmt.Sprintf("会话已结束但%s，%d 秒后第 %d/%d 次自动续跑…",
		waitReason, int(backoff.Seconds()), *attempt, maxAttempts)
	if progressCallback != nil {
		progressCallback("eino_empty_response_continue", waitMsg, map[string]interface{}{
			"conversationId": conversationID,
			"source":         "eino",
			"continueKind":   continueKind,
			"attempt":        *attempt,
			"maxAttempts":    maxAttempts,
			"backoffSec":     int(backoff.Seconds()),
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(backoff):
	}

	h.applyEinoTraceResumeSegment(conversationID, result, curHistory, curFinalMessage, inject)
	if progressCallback != nil {
		progressCallback("eino_empty_response_continue", "已恢复上下文，正在续跑…", map[string]interface{}{
			"conversationId": conversationID,
			"source":         "eino",
			"continueKind":   continueKind,
			"attempt":        *attempt,
			"maxAttempts":    maxAttempts,
			"contextSource":  continueKind,
		})
	}
	return true
}
