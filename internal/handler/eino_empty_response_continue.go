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

// newEinoSegment scopes interrupt-and-continue to this segment while retaining
// the request's absolute deadline and terminal user cancellation.
func (r *agentRunDeadline) newEinoSegment() (context.Context, context.CancelCauseFunc, context.Context, context.CancelFunc) {
	ctx, cancelWithCause, segmentCancel := r.newSegment(multiagent.ErrInterruptContinue)
	return ctx, cancelWithCause, ctx, segmentCancel
}

// rebindEinoRunningTask replaces only the segment cancellation chain. All
// automatic, empty-response and interrupt continuations share the request root.
func (h *AgentHandler) rebindEinoRunningTask(run *agentRunDeadline, conversationID string, segmentCancel context.CancelFunc) (context.Context, context.CancelCauseFunc, context.Context, context.CancelFunc) {
	if segmentCancel != nil {
		segmentCancel()
	}
	baseCtx, cancelWithCause, taskCtx, newSegmentCancel := run.newEinoSegment()
	h.tasks.BindTaskCancel(conversationID, cancelWithCause)
	if agentRunContextError(taskCtx) == nil {
		h.tasks.UpdateTaskStatus(conversationID, "running")
	}
	return baseCtx, cancelWithCause, taskCtx, newSegmentCancel
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
	if result != nil && result.ReportSubmitted {
		// Submitted (including empty) exit is handled by the finalizer's report
		// and pending-tool checks, not a second competing retry policy.
		return false
	}
	inject, continueKind := multiagent.EinoResponseContinueInstruction(result, preferFinalReport)
	if agentRunContextError(taskCtx) != nil {
		return false
	}
	if result == nil || inject == "" || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	announce := multiagent.ShouldAnnounceEmptyResponseContinue(result)
	if !announce && continueKind == multiagent.EinoResponseContinueKindEmpty {
		inject = multiagent.FormatFirstRunEmptyRetryUserMessage()
	}
	if pending, err := h.pendingFinalizationTools(taskCtx, conversationID, result.MCPExecutionIDs); err != nil || len(pending) > 0 {
		// Rebinding this segment would cancel tools before their results are
		// read. Let the finalizer wait and resume through the governed path.
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
	if progressCallback != nil && announce {
		progressCallback("eino_empty_response_continue", waitMsg, map[string]interface{}{
			"conversationId": conversationID,
			"source":         "eino",
			"continueKind":   continueKind,
			"attempt":        *attempt,
			"maxAttempts":    maxAttempts,
			"backoffSec":     int(backoff.Seconds()),
		})
	} else if !announce && h.logger != nil {
		h.logger.Info("首次执行没有可恢复上下文，空回复重试不展示自动续跑",
			zap.String("conversationId", conversationID),
			zap.String("continueKind", continueKind),
			zap.Int("attempt", *attempt))
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(backoff):
	}
	if agentRunContextError(taskCtx) != nil {
		return false
	}

	h.applyEinoTraceResumeSegment(conversationID, result, curHistory, curFinalMessage, inject)
	if progressCallback != nil && announce {
		progressCallback("eino_empty_response_continue", "已恢复上下文，正在续跑…", map[string]interface{}{
			"conversationId": conversationID,
			"source":         "eino",
			"continueKind":   continueKind,
			"attempt":        *attempt,
			"maxAttempts":    maxAttempts,
			"contextSource":  continueKind,
		})
	}
	return agentRunContextError(taskCtx) == nil
}
