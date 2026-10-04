package handler

import (
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

// finalizeAgentRunForDelivery 使用默认策略对 RunResult 做最终回复判定并落库。
func (h *AgentHandler) finalizeAgentRunForDelivery(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
	reasoningContent string,
) agentfinalizer.Decision {
	return h.finalizeAgentRunForDeliveryWithPolicy(conversationID, assistantMessageID, agentMode, result, mcpExecutionIDs, reasoningContent, false)
}

func (h *AgentHandler) finalizeAgentRunForDeliveryWithPolicy(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
	reasoningContent string,
	requireExecutionEvidence bool,
	requireCoverageEvidence ...bool,
) agentfinalizer.Decision {
	decision := agentfinalizer.FromRunResult(h.db, result, agentfinalizer.Input{
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		RequireExecutionEvidence: requireExecutionEvidence,
		RequireCoverageEvidence:  firstPolicyFlag(requireCoverageEvidence),
	})
	return h.persistFinalizationDecision(conversationID, assistantMessageID, agentMode, mcpExecutionIDs, reasoningContent, decision)
}

// decideAgentRunForDeliveryWithPolicy 只做判定与 RunResult 回填，不写库（供需要自己组织 SSE 的调用点使用）。
func (h *AgentHandler) decideAgentRunForDeliveryWithPolicy(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
	requireExecutionEvidence bool,
	requireCoverageEvidence ...bool,
) agentfinalizer.Decision {
	return agentfinalizer.FromRunResult(h.db, result, agentfinalizer.Input{
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		RequireExecutionEvidence: requireExecutionEvidence,
		RequireCoverageEvidence:  firstPolicyFlag(requireCoverageEvidence),
	})
}

func (h *AgentHandler) decideAgentRunForDelivery(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	result *multiagent.RunResult,
	mcpExecutionIDs []string,
) agentfinalizer.Decision {
	return agentfinalizer.FromRunResult(h.db, result, agentfinalizer.Input{
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		RequireExecutionEvidence: false,
	})
}

// persistFinalizationDecision preserves the candidate/checks in process details
// and persists either a verified answer or an explicitly incomplete report.
// Callers must use the returned decision for the same SSE/JSON delivery metadata.
func (h *AgentHandler) persistFinalizationDecision(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	mcpExecutionIDs []string,
	reasoningContent string,
	decision agentfinalizer.Decision,
) agentfinalizer.Decision {
	decision.ConversationID, decision.AssistantMessageID, decision.AgentMode = conversationID, assistantMessageID, agentMode
	decision = finalizationStoppedDecision(decision, nil)
	decision = agentfinalizer.PrepareStoppedDelivery(h.db, decision)
	if assistantMessageID == "" || h.db == nil {
		return decision
	}
	_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "finalization_check", finalizationCheckMessage(decision), decision)
	text := decision.FinalText
	if !decision.Finalizable {
		text = finalizationBlockedMessage(decision)
	}
	// This method updates text/trace metadata only; it does not mark the
	// assessment as completed. Its true status is saved independently below.
	if err := h.db.UpdateAssistantMessageFinalize(assistantMessageID, text, mcpExecutionIDs, reasoningContent); err != nil {
		if h.logger != nil {
			h.logger.Warn("更新交付助手消息失败", zap.Error(err), zap.String("conversationId", conversationID), zap.String("agentMode", agentMode))
		}
	}
	h.saveGovernedRunDecision(conversationID, decision)
	return decision
}

// finalizeCandidateForDelivery 面向只有候选文本（无 RunResult）的收尾路径，如工作流集成、机器人。
func (h *AgentHandler) finalizeCandidateForDelivery(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	response string,
	mcpExecutionIDs []string,
	awaitingHITL bool,
	reasoningContent string,
) agentfinalizer.Decision {
	return h.finalizeCandidateForDeliveryWithPolicy(conversationID, assistantMessageID, agentMode, response, mcpExecutionIDs, awaitingHITL, reasoningContent, false)
}

func (h *AgentHandler) finalizeCandidateForDeliveryWithPolicy(
	conversationID string,
	assistantMessageID string,
	agentMode string,
	response string,
	mcpExecutionIDs []string,
	awaitingHITL bool,
	reasoningContent string,
	requireExecutionEvidence bool,
	requireCoverageEvidence ...bool,
) agentfinalizer.Decision {
	decision := agentfinalizer.Decide(h.db, agentfinalizer.Input{
		Response:                 response,
		ConversationID:           conversationID,
		AssistantMessageID:       assistantMessageID,
		AgentMode:                agentMode,
		MCPExecutionIDs:          mcpExecutionIDs,
		AwaitingHITL:             awaitingHITL,
		RequireExecutionEvidence: requireExecutionEvidence,
		RequireCoverageEvidence:  firstPolicyFlag(requireCoverageEvidence),
	})
	return h.persistFinalizationDecision(conversationID, assistantMessageID, agentMode, mcpExecutionIDs, reasoningContent, decision)
}

func finalizationCheckMessage(d agentfinalizer.Decision) string {
	if d.Finalizable {
		return "最终回复检查通过。"
	}
	if d.DeliveryAvailable && d.RunTerminated && d.DeliveryKind == agentfinalizer.DeliveryKindPartialReport {
		return "本次运行已停止，已交付阶段报告；完整评估未通过。候选原文与完整诊断保留在记录数据中。"
	}
	return finalizationBlockedMessage(d)
}

// finalizationBlockedMessage 生成用户可见的阻断文案（不暴露敏感细节，只说明未达最终化条件）。
func finalizationBlockedMessage(d agentfinalizer.Decision) string {
	if d.DeliveryAvailable && d.RunTerminated && d.DeliveryKind == agentfinalizer.DeliveryKindPartialReport && strings.TrimSpace(d.DeliveryText) != "" {
		return d.DeliveryText
	}
	parts := []string{"任务尚未达到最终回复条件，暂不生成成功结论。"}
	if d.CompletionReason != "" {
		parts = append(parts, "原因: "+d.CompletionReason)
	}
	if len(d.PendingExecutionIDs) > 0 {
		parts = append(parts, fmt.Sprintf("仍有 %d 个工具执行未结束: %s", len(d.PendingExecutionIDs), strings.Join(d.PendingExecutionIDs, ", ")))
	}
	if d.CoverageProgressKnown {
		parts = append(parts, fmt.Sprintf("独立候选库存：共 %d 组，已关联有证据的处置记录 %d 组，未完成 %d 组；这不是漏洞数量或已验证安全数量。", d.CoverageInventoryGroups, d.CoverageMappedGroups, d.CoverageUnresolvedGroups))
	}
	if d.CoverageRepairBlocked {
		parts = append(parts, "已停止自动逐 URL 补写。原始明细仍在库存/结果工件中，应先按范围、当前性与业务功能分类，不能统一标记为 N/A、否定或安全。")
	}
	if mcp.IsAgentRunBudgetReason(d.CompletionReason) && d.FinalText != "" {
		parts = append(parts, d.FinalText)
	}
	if len(d.MissingChecks) > 0 {
		checks := d.MissingChecks
		if (d.CoverageRepairBlocked || mcp.IsAgentRunBudgetReason(d.CompletionReason)) && len(checks) > 20 {
			checks = checks[:20]
			parts = append(parts, fmt.Sprintf("以下仅显示前 20 条；完整 %d 条诊断保留在本次 finalization_check 过程记录中。", len(d.MissingChecks)))
		}
		parts = append(parts, "缺失检查: "+strings.Join(checks, "; "))
	}
	return strings.Join(parts, "\n")
}

// persistRunStopAndSendDelivery keeps failed/cancelled/timeout runs readable
// without promoting their candidate text or treating pending tools as finished.
func (h *AgentHandler) persistRunStopAndSendDelivery(conversationID, messageID, agentMode, status string, result *multiagent.RunResult, ids []string, sendEvent func(string, string, interface{})) {
	d := agentfinalizer.Decision{Status: status, CompletionReason: status}
	reasoning := ""
	if result != nil {
		d.FinalText, d.ReportSubmitted = result.Response, result.ReportSubmitted
		d.MissingChecks = append([]string(nil), result.MissingChecks...)
		d.PendingExecutionIDs = append([]string(nil), result.PendingExecutionIDs...)
		reasoning = multiagent.AggregatedReasoningFromTraceJSON(result.LastAgentTraceInput)
	}
	d = h.persistFinalizationDecision(conversationID, messageID, agentMode, ids, reasoning, d)
	if d.DeliveryAvailable {
		sendEvent("response", d.DeliveryText, finalizationResponsePayload(d, nil))
	}
	sendEvent("done", "", finalizationResponsePayload(d, nil))
}

func finalizationResponsePayload(d agentfinalizer.Decision, extra map[string]interface{}) map[string]interface{} {
	return agentfinalizer.ResponsePayload(d, extra)
}

func requestRequiresExecutionEvidence(req *ChatRequest) bool {
	return req != nil && req.Finalization.RequireExecutionEvidence != nil && *req.Finalization.RequireExecutionEvidence
}

func firstPolicyFlag(flags []bool) bool {
	return len(flags) > 0 && flags[0]
}

func requestRequiresCoverageEvidence(req *ChatRequest) bool {
	return req != nil && req.Finalization.RequireCoverageEvidence != nil && *req.Finalization.RequireCoverageEvidence
}
