package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/vision"
	workflowrunner "cyberstrike-ai/internal/workflow"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (h *AgentHandler) roleForWorkflow(req *ChatRequest) (config.RoleConfig, bool) {
	if h == nil || h.config == nil || h.config.Roles == nil || req == nil {
		return config.RoleConfig{}, false
	}
	roleName := strings.TrimSpace(req.Role)
	if roleName == "" {
		return config.RoleConfig{}, false
	}
	role, ok := h.config.Roles[roleName]
	if !ok || !role.Enabled {
		return config.RoleConfig{}, false
	}
	if role.Name == "" {
		role.Name = roleName
	}
	if !workflowrunner.ShouldAutoRunRoleWorkflow(role) {
		return config.RoleConfig{}, false
	}
	return role, true
}

func (h *AgentHandler) runRoleWorkflowStreamIfBound(
	c *gin.Context,
	req *ChatRequest,
	prep *multiAgentPrepared,
	sendEvent func(eventType, message string, data interface{}),
) bool {
	role, ok := h.roleForWorkflow(req)
	if !ok || prep == nil {
		return false
	}
	runCfg, _, err := h.configForAIChannel(req.AIChannelID)
	if err != nil {
		sendEvent("error", err.Error(), nil)
		sendEvent("done", "", map[string]interface{}{"conversationId": prep.ConversationID})
		return true
	}
	conversationID := prep.ConversationID
	assistantMessageID := prep.AssistantMessageID
	userMessage := ""
	if req != nil {
		userMessage = req.Message
	}
	h.recordRunTargets(conversationID, userMessage)

	taskStatus := "completed"
	taskOwned := false
	defer func() {
		if taskOwned {
			h.tasks.FinishTask(conversationID, taskStatus)
		}
	}()

	if c == nil || c.Request == nil {
		return false
	}
	baseCtx, cancelWithCause := context.WithCancelCause(detachedAgentContext(c.Request.Context()))
	defer cancelWithCause(nil)
	taskCtx, timeoutCancel := context.WithTimeout(baseCtx, defaultAgentRunTimeout)
	defer timeoutCancel()
	taskCtx = vision.WithSessionConfig(taskCtx, runCfg.Vision, runCfg.OpenAI)

	if _, err := h.tasks.StartTask(conversationID, userMessage, cancelWithCause); err != nil {
		var errorMsg string
		if errors.Is(err, ErrTaskAlreadyRunning) {
			errorMsg = "⚠️ 当前会话已有任务正在执行中，请等待当前任务完成或点击「停止任务」后再尝试。"
			sendEvent("error", errorMsg, map[string]interface{}{
				"conversationId": conversationID,
				"errorType":      "task_already_running",
			})
		} else {
			errorMsg = "❌ 无法启动任务: " + err.Error()
			sendEvent("error", errorMsg, nil)
		}
		if assistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", errorMsg, time.Now(), assistantMessageID)
		}
		sendEvent("done", "", map[string]interface{}{"conversationId": conversationID})
		return true
	}
	h.tasks.SetTaskAgentMode(conversationID, "workflow")
	taskOwned = true
	sendEvent("task_started", "任务已启动", map[string]interface{}{"conversationId": conversationID})
	h.recordConversationAIChannel(conversationID, req.AIChannelID, runCfg)

	progress := h.createProgressCallback(taskCtx, cancelWithCause, conversationID, assistantMessageID, sendEvent)
	result, err := workflowrunner.RunRoleBoundWorkflow(taskCtx, workflowrunner.RunArgs{
		DB:                 h.db,
		Logger:             h.logger,
		Role:               role,
		AppCfg:             runCfg,
		Agent:              h.agent,
		ConversationID:     conversationID,
		ProjectID:          h.conversationProjectID(conversationID),
		UserMessage:        prep.FinalMessage,
		History:            prep.History,
		RoleTools:          prep.RoleTools,
		AgentsMarkdownDir:  h.agentsMarkdownDir,
		SystemPromptExtra:  h.agentSessionContextBlock(conversationID),
		AssistantMessageID: assistantMessageID,
		Progress:           progress,
	})
	if err != nil {
		cause := context.Cause(baseCtx)
		if errors.Is(cause, ErrTaskCancelled) {
			taskStatus = "cancelled"
			h.tasks.UpdateTaskStatus(conversationID, taskStatus)
			cancelMsg := "任务已被用户取消，后续操作已停止。"
			if assistantMessageID != "" {
				if err := h.appendAssistantMessageNotice(assistantMessageID, cancelMsg); err != nil {
					h.logger.Warn("更新取消后的助手消息失败", zap.Error(err))
				}
				_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "cancelled", cancelMsg, nil)
			}
			sendEvent("cancelled", cancelMsg, map[string]interface{}{
				"conversationId": conversationID,
				"messageId":      assistantMessageID,
			})
			h.persistRunStopAndSendDelivery(conversationID, assistantMessageID, "workflow", taskStatus, nil, nil, sendEvent)
			return true
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(context.Cause(taskCtx), context.DeadlineExceeded) {
			taskStatus = "timeout"
			h.tasks.UpdateTaskStatus(conversationID, taskStatus)
			timeoutMsg := "任务执行超时，已自动终止。"
			if assistantMessageID != "" {
				_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", timeoutMsg, time.Now(), assistantMessageID)
				_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "timeout", timeoutMsg, nil)
			}
			sendEvent("error", timeoutMsg, map[string]interface{}{
				"conversationId": conversationID,
				"messageId":      assistantMessageID,
				"errorType":      "timeout",
			})
			h.persistRunStopAndSendDelivery(conversationID, assistantMessageID, "workflow", taskStatus, nil, nil, sendEvent)
			return true
		}
		errMsg := "执行角色绑定流程失败: " + err.Error()
		taskStatus = "failed"
		h.tasks.UpdateTaskStatus(conversationID, taskStatus)
		if assistantMessageID != "" {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", errMsg, time.Now(), assistantMessageID)
			_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "error", errMsg, nil)
		}
		sendEvent("error", errMsg, map[string]interface{}{"conversationId": conversationID})
		h.persistRunStopAndSendDelivery(conversationID, assistantMessageID, "workflow", taskStatus, nil, nil, sendEvent)
		return true
	}
	// 最终回复治理：workflow 等待 HITL 时不允许 final；候选文本通过 finalizer 才交付。
	decision := h.finalizeCandidateForDeliveryWithPolicy(
		prep.ConversationID,
		prep.AssistantMessageID,
		"workflow",
		result.Response,
		nil,
		result.AwaitingHITL,
		"",
		requestRequiresExecutionEvidence(req),
		requestRequiresCoverageEvidence(req),
	)
	payload := map[string]interface{}{
		"workflowRunId": result.RunID,
	}
	if result.AwaitingHITL {
		payload["workflowStatus"] = "awaiting_hitl"
		payload["awaitingHitl"] = true
	}
	responseText := decision.FinalText
	if !decision.Finalizable {
		responseText = finalizationBlockedMessage(decision)
	}
	taskStatus = decision.Status
	h.tasks.UpdateTaskStatus(conversationID, taskStatus)
	sendEvent("response", responseText, finalizationResponsePayload(decision, payload))
	sendEvent("done", "", finalizationResponsePayload(decision, payload))
	return true
}

func (h *AgentHandler) runRoleWorkflowJSONIfBound(c *gin.Context, req *ChatRequest, prep *multiAgentPrepared) bool {
	role, ok := h.roleForWorkflow(req)
	if !ok || prep == nil {
		return false
	}
	runCfg, _, err := h.configForAIChannel(req.AIChannelID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "conversationId": prep.ConversationID})
		return true
	}
	conversationID := prep.ConversationID
	assistantMessageID := prep.AssistantMessageID
	userMessage := ""
	if req != nil {
		userMessage = req.Message
	}
	h.recordRunTargets(conversationID, userMessage)

	taskStatus := "completed"
	taskOwned := false
	defer func() {
		if taskOwned {
			h.tasks.FinishTask(conversationID, taskStatus)
		}
	}()

	baseCtx, cancelWithCause := context.WithCancelCause(c.Request.Context())
	defer cancelWithCause(nil)
	taskCtx, timeoutCancel := context.WithTimeout(baseCtx, defaultAgentRunTimeout)
	defer timeoutCancel()
	taskCtx = vision.WithSessionConfig(taskCtx, runCfg.Vision, runCfg.OpenAI)

	if _, err := h.tasks.StartTask(conversationID, userMessage, cancelWithCause); err != nil {
		if errors.Is(err, ErrTaskAlreadyRunning) {
			c.JSON(http.StatusConflict, gin.H{
				"error":          "⚠️ 当前会话已有任务正在执行中，请等待当前任务完成或点击「停止任务」后再尝试。",
				"conversationId": conversationID,
				"errorType":      "task_already_running",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ 无法启动任务: " + err.Error()})
		}
		return true
	}
	h.tasks.SetTaskAgentMode(conversationID, "workflow")
	taskOwned = true
	h.recordConversationAIChannel(conversationID, req.AIChannelID, runCfg)

	progress := h.createProgressCallback(taskCtx, cancelWithCause, conversationID, assistantMessageID, nil)
	result, err := workflowrunner.RunRoleBoundWorkflow(taskCtx, workflowrunner.RunArgs{
		DB:                 h.db,
		Logger:             h.logger,
		Role:               role,
		AppCfg:             runCfg,
		Agent:              h.agent,
		ConversationID:     conversationID,
		ProjectID:          h.conversationProjectID(conversationID),
		UserMessage:        prep.FinalMessage,
		History:            prep.History,
		RoleTools:          prep.RoleTools,
		AgentsMarkdownDir:  h.agentsMarkdownDir,
		SystemPromptExtra:  h.agentSessionContextBlock(conversationID),
		AssistantMessageID: assistantMessageID,
		Progress:           progress,
	})
	if err != nil {
		d := h.persistRuntimeFailureForDelivery(taskCtx, conversationID, assistantMessageID, "workflow", nil, nil, err)
		taskStatus = d.Status
		h.tasks.UpdateTaskStatus(conversationID, taskStatus)
		statusCode := http.StatusInternalServerError
		if taskStatus == "cancelled" {
			statusCode = http.StatusOK
		}
		c.JSON(statusCode, finalizationResponsePayload(d, map[string]interface{}{"error": "执行角色绑定流程失败: " + err.Error(), "response": finalizationBlockedMessage(d)}))
		return true
	}
	// 最终回复治理：workflow 等待 HITL 时不允许 final。
	decision := h.finalizeCandidateForDeliveryWithPolicy(
		prep.ConversationID,
		prep.AssistantMessageID,
		"workflow",
		result.Response,
		nil,
		result.AwaitingHITL,
		"",
		requestRequiresExecutionEvidence(req),
		requestRequiresCoverageEvidence(req),
	)
	responseText := decision.FinalText
	if !decision.Finalizable {
		responseText = finalizationBlockedMessage(decision)
	}
	taskStatus = decision.Status
	h.tasks.UpdateTaskStatus(conversationID, taskStatus)
	c.JSON(http.StatusOK, gin.H{
		"response":            responseText,
		"finalized":           decision.Finalized,
		"finalizable":         decision.Finalizable,
		"deliveryAvailable":   decision.DeliveryAvailable,
		"deliveryKind":        decision.DeliveryKind,
		"runTerminated":       decision.RunTerminated,
		"deliveryText":        decision.DeliveryText,
		"status":              decision.Status,
		"completionReason":    decision.CompletionReason,
		"missingChecks":       decision.MissingChecks,
		"pendingExecutionIds": decision.PendingExecutionIDs,
		"conversationId":      prep.ConversationID,
		"assistantMessageId":  prep.AssistantMessageID,
		"agentMode":           "workflow",
		"workflowRunId":       result.RunID,
		"workflowStatus":      result.Status,
		"awaitingHitl":        result.AwaitingHITL,
	})
	return true
}
