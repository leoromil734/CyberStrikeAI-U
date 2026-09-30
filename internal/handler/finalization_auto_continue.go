package handler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

// finalizationAutoContinueMaxAttempts 最终回复未收敛时最多自动续跑段数；
// 达到上限仍未收敛才写入 blocked，避免模型「总结代替执行」或「说到一半就停」。
const finalizationAutoContinueMaxAttempts = 2

// finalizationPendingWaitTimeout 判定为 pending_tool_executions 时，等待后台执行结束的上限。
// 超过上限仍按阻塞收尾，避免无限期占用 worker。
const finalizationPendingWaitTimeout = 20 * time.Minute

// finalizationPendingPollInterval pending 工具执行的轮询间隔。
const finalizationPendingPollInterval = 5 * time.Second

func shouldAutoContinueAfterFinalization(d agentfinalizer.Decision, attempt int) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	if attempt >= finalizationAutoContinueMaxAttempts {
		return false
	}
	switch d.CompletionReason {
	case agentfinalizer.ReasonMissingEvidence,
		agentfinalizer.ReasonCoverageIncomplete,
		// 有工具执行还在跑：先等它们结束再续跑，而不是直接终止（并把正在跑的工具取消）。
		agentfinalizer.ReasonPendingTools,
		// 候选是没说完的半截话：再跑一段，让模型把结论补完。
		agentfinalizer.ReasonIncompleteCandidate:
		return true
	default:
		return false
	}
}

// hasPendingToolExecution 判断给定执行 ID 中是否仍有 queued/running。
func (h *AgentHandler) hasPendingToolExecution(ids []string) bool {
	if h == nil || h.db == nil {
		return false
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		exec, err := h.db.GetToolExecution(id)
		if err != nil || exec == nil {
			continue
		}
		switch strings.TrimSpace(exec.Status) {
		case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning:
			return true
		}
	}
	return false
}

// waitFinalizationPendingExecutions 等待 pending 工具执行结束（上限 finalizationPendingWaitTimeout）。
// 返回 true 表示都已结束（含无法查询的情况），可以安全续跑。
func (h *AgentHandler) waitFinalizationPendingExecutions(ctx context.Context, ids []string) bool {
	if !h.hasPendingToolExecution(ids) {
		return true
	}
	deadline := time.Now().Add(finalizationPendingWaitTimeout)
	for {
		if !h.hasPendingToolExecution(ids) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(finalizationPendingPollInterval):
		}
	}
}

// tryAutoContinueAfterFinalization 在判定为「缺执行证据 / 有工具执行未结束 / 候选话没说完」时基于已有轨迹续跑一段。
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
	if !shouldAutoContinueAfterFinalization(decision, *attempt) || result == nil {
		return false
	}
	// pending 工具执行：先等它们结束，再续跑让模型读取结果。
	if decision.CompletionReason == agentfinalizer.ReasonPendingTools {
		if progressCallback != nil {
			progressCallback("finalization_waiting_tools", fmt.Sprintf("仍有 %d 个工具执行在运行，等待其结束后继续…", len(decision.PendingExecutionIDs)), map[string]interface{}{
				"conversationId":      conversationID,
				"source":              "finalizer",
				"status":              decision.Status,
				"completionReason":    decision.CompletionReason,
				"pendingExecutionIds": decision.PendingExecutionIDs,
				"waitTimeoutSeconds":  int(finalizationPendingWaitTimeout / time.Second),
			})
		}
		if !h.waitFinalizationPendingExecutions(taskCtx, decision.PendingExecutionIDs) {
			if h.logger != nil {
				h.logger.Warn("等待 pending 工具执行超时，按阻塞收尾",
					zap.String("conversationId", conversationID),
					zap.Int("pendingCount", len(decision.PendingExecutionIDs)),
					zap.Strings("pendingExecutionIds", decision.PendingExecutionIDs))
			}
			return false
		}
	}
	if !multiagent.HasEinoResumeTrace(result) {
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
	// 一般续跑只恢复已有轨迹。覆盖检查失败时额外传入宿主生成的
	// 缺口清单，避免模型重复提交同一份报告；不写入用户消息表。
	*curFinalMessage = ""
	if decision.CompletionReason == agentfinalizer.ReasonCoverageIncomplete {
		*curFinalMessage = formatCoverageContinueMessage(decision.MissingChecks)
	}
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
			"contextInjection":    decision.CompletionReason == agentfinalizer.ReasonCoverageIncomplete,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(finalizationAutoContinueBackoff(*attempt)):
		return true
	}
}

func formatCoverageContinueMessage(checks []string) string {
	var b strings.Builder
	b.WriteString("【系统自动续跑 / Auto resume】\n结构化覆盖检查尚未通过。只补当前评估缺口，不重复已完成步骤，不扩大授权范围，保留用户排除项。查阅 pentest-blackboard/references/coverage-contract.md 并读取相应事实；blocked/N/A 必须有原始证据和具体原因，不得把未测改成已覆盖。\n")
	for i, check := range checks {
		if i >= 20 {
			b.WriteString("- 其余缺口请在补齐本批后继续复核。\n")
			break
		}
		line := []rune(strings.TrimSpace(check))
		if len(line) > 200 {
			line = line[:200]
		}
		b.WriteString("- " + string(line) + "\n")
	}
	return b.String()
}

func finalizationAutoContinueBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 500 * time.Millisecond
	}
	return time.Duration(attempt) * time.Second
}
