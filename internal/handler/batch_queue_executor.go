package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

const batchQueueWorkerIdlePoll = 200 * time.Millisecond

// executeBatchQueue 使用并发 worker 池执行批量任务队列。
func (h *AgentHandler) executeBatchQueue(queueID string) {
	defer h.batchTaskManager.UnmarkQueueExecutor(queueID)

	queue, exists := h.batchTaskManager.GetBatchQueue(queueID)
	if !exists {
		return
	}
	concurrency := normalizeBatchQueueConcurrency(queue.Concurrency)
	h.logger.Info("开始执行批量任务队列", zap.String("queueId", queueID), zap.Int("concurrency", concurrency))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.runBatchQueueWorker(queueID)
		}()
	}
	wg.Wait()

	h.tryFinalizeBatchQueue(queueID)
}

func (h *AgentHandler) runBatchQueueWorker(queueID string) {
	for {
		queue, exists := h.batchTaskManager.GetBatchQueue(queueID)
		if batchQueueExecutionShouldStop(queue, exists) {
			return
		}

		task, ok := h.batchTaskManager.ClaimNextPendingTask(queueID)
		if !ok {
			if !h.batchTaskManager.HasRunningTasks(queueID) {
				return
			}
			time.Sleep(batchQueueWorkerIdlePoll)
			continue
		}

		queue, _ = h.batchTaskManager.GetBatchQueue(queueID)
		if queue == nil {
			return
		}

		h.batchTaskManager.UpdateTaskStatus(queueID, task.ID, BatchTaskStatusRunning, "", "")
		h.executeOneBatchSubTask(queueID, queue, task)

		if h.batchTaskManager.TakeSingleRunTaskIfMatch(queueID, task.ID) {
			h.batchTaskManager.UpdateQueueStatus(queueID, BatchQueueStatusPaused)
			h.logger.Info("单条执行完成，队列已暂停", zap.String("queueId", queueID), zap.String("taskId", task.ID))
			return
		}

		queue, exists = h.batchTaskManager.GetBatchQueue(queueID)
		if batchQueueExecutionShouldStop(queue, exists) {
			if !exists {
				h.logger.Warn("批量队列在执行收尾时已不存在，安全退出", zap.String("queueId", queueID))
			}
			return
		}
	}
}

func (h *AgentHandler) tryFinalizeBatchQueue(queueID string) {
	queue, exists := h.batchTaskManager.GetBatchQueue(queueID)
	if !exists || queue == nil {
		return
	}
	if queue.Status != BatchQueueStatusRunning {
		return
	}
	if h.batchTaskManager.HasPendingOrRunningTasks(queueID) {
		return
	}

	lastRunErr := ""
	var blockedReasons []string
	for _, t := range queue.Tasks {
		if t == nil {
			continue
		}
		if t.Status == BatchTaskStatusBlocked {
			blockedReasons = append(blockedReasons, fmt.Sprintf("任务 %s: %s", t.ID, t.Error))
		} else if t.Status == BatchTaskStatusFailed && t.Error != "" {
			lastRunErr = t.Error
		}
	}
	if len(blockedReasons) > 0 {
		blockedCount := len(blockedReasons)
		if lastRunErr != "" {
			blockedReasons = append(blockedReasons, lastRunErr)
		}
		h.batchTaskManager.SetLastRunError(queueID, strings.Join(blockedReasons, "\n"))
		h.batchTaskManager.UpdateQueueStatus(queueID, BatchQueueStatusPaused)
		h.logger.Info("批量任务队列存在未最终化的子任务，已暂停等待恢复", zap.String("queueId", queueID), zap.Int("blockedCount", blockedCount))
		return
	}
	h.batchTaskManager.SetLastRunError(queueID, lastRunErr)
	h.batchTaskManager.UpdateQueueStatus(queueID, BatchQueueStatusCompleted)
	h.logger.Info("批量任务队列执行完成", zap.String("queueId", queueID))
}

// executeOneBatchSubTask 执行单条批量子任务（各自独立会话）。
func (h *AgentHandler) executeOneBatchSubTask(queueID string, queue *BatchTaskQueue, task *BatchTask) {
	ownerUserID := h.db.GetResourceOwner("batch_task", queueID)
	access, accessErr := h.db.ResolveRBACAccess(ownerUserID)
	if accessErr != nil || access == nil || !access.User.Enabled {
		h.batchTaskManager.UpdateTaskStatus(queueID, task.ID, BatchTaskStatusFailed, "", "队列所有者不存在或已禁用")
		return
	}
	principal := authctx.NewPrincipalWithScopes(access.User.ID, access.User.Username, access.Scope, access.Permissions, access.PermissionScopes)
	title := safeTruncateString(task.Message, 50)
	batchMeta := audit.ConversationCreateMeta("batch_task")
	batchMeta.ProjectID = effectiveProjectID(h.config, queue.ProjectID)
	conv, err := h.db.CreateConversation(title, batchMeta)
	if err != nil {
		h.logger.Error("创建对话失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(err))
		h.batchTaskManager.UpdateTaskStatus(queueID, task.ID, BatchTaskStatusFailed, "", "创建对话失败: "+err.Error())
		return
	}
	conversationID := conv.ID
	_ = h.db.SetResourceOwner("conversation", conversationID, access.User.ID)
	_ = h.db.AssignResourceToUser(access.User.ID, "conversation", conversationID)

	h.batchTaskManager.UpdateTaskStatusWithConversationID(queueID, task.ID, BatchTaskStatusRunning, "", "", conversationID)

	finalMessage := task.Message
	var roleTools []string
	if queue.Role != "" && queue.Role != "默认" {
		if h.config.Roles != nil {
			if role, exists := h.config.Roles[queue.Role]; exists && role.Enabled {
				if role.UserPrompt != "" {
					finalMessage = role.UserPrompt + "\n\n" + task.Message
					h.logger.Info("应用角色用户提示词", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("role", queue.Role))
				}
				if len(role.Tools) > 0 {
					roleTools = role.Tools
					h.logger.Info("使用角色配置的工具列表", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("role", queue.Role), zap.Int("toolCount", len(roleTools)))
				}
			}
		}
	}

	if _, err = h.db.AddMessage(conversationID, "user", task.Message, nil); err != nil {
		h.logger.Error("保存用户消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID), zap.Error(err))
	}

	assistantMsg, err := h.db.AddMessage(conversationID, "assistant", "处理中...", nil)
	if err != nil {
		h.logger.Error("创建助手消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID), zap.Error(err))
		assistantMsg = nil
	}

	var assistantMessageID string
	if assistantMsg != nil {
		assistantMessageID = assistantMsg.ID
	}

	h.logger.Info("执行批量任务",
		zap.String("queueId", queueID),
		zap.String("taskId", task.ID),
		zap.String("message", task.Message),
		zap.String("role", queue.Role),
		zap.String("conversationId", conversationID),
		zap.String("aiChannelId", strings.TrimSpace(task.AIChannelID)),
		zap.Int("modelRetryMax", queue.ModelRetryMax),
	)

	principalCtx := authctx.WithPrincipal(context.Background(), principal)
	baseCtx, cancelWithCause := context.WithCancelCause(principalCtx)
	taskCtx, timeoutCancel := context.WithTimeout(baseCtx, 6*time.Hour)

	registered := false
	// 默认失败；只有最终化检查通过后才允许登记 completed。
	finishStatus := BatchTaskStatusFailed
	var decision agentfinalizer.Decision

	defer func() {
		h.batchTaskManager.SetTaskCancel(queueID, task.ID, nil)
		timeoutCancel()
		if registered {
			h.finishBatchSubTask(conversationID, finishStatus, decision)
		}
		cancelWithCause(nil)
	}()

	sendEvent := func(eventType, message string, data interface{}) {
		if h.taskEventBus == nil {
			return
		}
		ev := StreamEvent{Type: eventType, Message: message, Data: data}
		b, err := json.Marshal(ev)
		if err != nil {
			b = []byte(`{"type":"error","message":"marshal failed"}`)
		}
		line := make([]byte, 0, len(b)+8)
		line = append(line, []byte("data: ")...)
		line = append(line, b...)
		line = append(line, '\n', '\n')
		h.taskEventBus.Publish(conversationID, line)
	}

	if _, err := h.tasks.StartTask(conversationID, task.Message, cancelWithCause); err != nil {
		h.logger.Warn("批量队列子任务注册会话运行状态失败",
			zap.String("queueId", queueID),
			zap.String("taskId", task.ID),
			zap.String("conversationId", conversationID),
			zap.Error(err))
		failMsg := err.Error()
		if errors.Is(err, ErrTaskAlreadyRunning) {
			failMsg = "会话已有任务正在执行，无法在该会话上并行启动批量子任务"
		}
		h.batchTaskManager.UpdateTaskStatus(queueID, task.ID, BatchTaskStatusFailed, "", failMsg)
		return
	}
	registered = true
	h.batchTaskManager.SetTaskCancel(queueID, task.ID, timeoutCancel)

	progressCallback := h.createProgressCallback(taskCtx, cancelWithCause, conversationID, assistantMessageID, sendEvent)
	taskCtx = mcp.WithMCPConversationID(taskCtx, conversationID)
	taskCtx = mcp.WithToolRunRegistry(taskCtx, h.tasks)
	taskCtx = mcp.WithEinoExecuteRunRegistry(taskCtx, h.tasks)

	useBatchMulti := false
	batchOrch := "deep"
	am := strings.TrimSpace(strings.ToLower(queue.AgentMode))
	if am == "multi" {
		am = "deep"
	}
	if batchQueueWantsEino(queue.AgentMode) && h.config != nil && h.config.MultiAgent.Enabled {
		useBatchMulti = true
		batchOrch = config.NormalizeMultiAgentOrchestration(am)
	} else if queue.AgentMode == "" && h.config != nil && h.config.MultiAgent.Enabled && h.config.MultiAgent.BatchUseMultiAgent {
		useBatchMulti = true
		batchOrch = "deep"
	}
	batchMode := am
	if batchMode == "" {
		if useBatchMulti {
			batchMode = batchOrch
		} else {
			batchMode = "eino_single"
		}
	}
	h.tasks.SetTaskAgentMode(conversationID, batchMode)
	h.recordConversationAIChannel(conversationID, task.AIChannelID)
	h.recordRunTargets(conversationID, task.Message)

	runCfg := h.batchTaskRunConfig(task.AIChannelID)
	maxRetry := normalizeModelErrorRetryMax(queue.ModelRetryMax)
	// 最终化治理：候选文本先过 finalizer，未收敛时按原因自动续跑（含等待仍在跑的异步工具）。
	segFinalMessage := finalMessage
	segHistory := []agent.ChatMessage{}
	finalizationAutoContinueAttempt := finalizationContinuationState{}
	upstreamErrorRetries := 0
	var resultMA *multiagent.RunResult
	var runErr error
	var cumulativeMCPExecutionIDs []string
	for {
		resultMA, runErr = nil, nil
		for attempt := 0; ; attempt++ {
			if attempt > 0 {
				if !h.waitBatchModelRetry(taskCtx, queueID, task, conversationID, assistantMessageID, attempt, maxRetry, runErr) {
					if taskCtx.Err() != nil {
						runErr = taskCtx.Err()
					}
					break
				}
			}
			switch {
			case useBatchMulti:
				resultMA, runErr = multiagent.RunDeepAgent(taskCtx, runCfg, &h.config.MultiAgent, h.agent, h.db, h.logger, conversationID, h.conversationProjectID(conversationID), segFinalMessage, segHistory, roleTools, progressCallback, h.agentsMarkdownDir, batchOrch, nil, h.agentSessionContextBlock(conversationID))
			default:
				if runCfg == nil {
					runErr = fmt.Errorf("服务器配置未加载")
				} else {
					resultMA, runErr = multiagent.RunEinoSingleChatModelAgent(taskCtx, runCfg, &h.config.MultiAgent, h.agent, h.db, h.logger, conversationID, h.conversationProjectID(conversationID), segFinalMessage, segHistory, roleTools, progressCallback, nil, h.agentSessionContextBlock(conversationID))
				}
			}
			if runErr == nil || attempt >= maxRetry || !batchModelErrorShouldRetry(baseCtx, taskCtx, runErr) {
				break
			}
			h.logger.Warn("批量任务因模型报错中断，将自动重试",
				zap.String("queueId", queueID),
				zap.String("taskId", task.ID),
				zap.String("conversationId", conversationID),
				zap.String("aiChannelId", strings.TrimSpace(task.AIChannelID)),
				zap.Int("attempt", attempt+1),
				zap.Int("maxRetries", maxRetry),
				zap.Error(runErr),
			)
		}
		if runErr != nil || resultMA == nil {
			break
		}

		cumulativeMCPExecutionIDs = mergeMCPExecutionIDLists(cumulativeMCPExecutionIDs, resultMA.MCPExecutionIDs)
		resultMA.MCPExecutionIDs = cumulativeMCPExecutionIDs
		decision = h.decideAgentRunForDelivery(conversationID, assistantMessageID, "batch", resultMA, cumulativeMCPExecutionIDs)
		// 上游网关以 HTTP 200 返回错误正文：不能当成功交付，按可重试的模型错误处理。
		if decision.CompletionReason == agentfinalizer.ReasonUpstreamErrorText {
			if upstreamErrorRetries < maxRetry {
				upstreamErrorRetries++
				h.logger.Warn("批量任务收到上游错误正文，将自动重试",
					zap.String("queueId", queueID),
					zap.String("taskId", task.ID),
					zap.String("conversationId", conversationID),
					zap.Int("attempt", upstreamErrorRetries),
					zap.Int("maxRetries", maxRetry),
					zap.String("candidateHead", safeTruncateString(decision.FinalText, 120)))
				if assistantMessageID != "" && h.db != nil {
					note := fmt.Sprintf("上游返回错误正文，正在第 %d/%d 次自动重试…", upstreamErrorRetries, maxRetry)
					_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", note, time.Now(), assistantMessageID)
					_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "retry", note, nil)
				}
				select {
				case <-taskCtx.Done():
					runErr = taskCtx.Err()
				case <-time.After(finalizationAutoContinueBackoff(upstreamErrorRetries)):
				}
				if runErr != nil {
					break
				}
				continue
			}
			runErr = fmt.Errorf("上游网关返回错误正文（已重试 %d 次）: %s", upstreamErrorRetries, safeTruncateString(decision.FinalText, 200))
			break
		}
		// 已可交付，或未收敛但仍有续跑机会（缺证据 / 有工具执行未结束 / 候选话没说完）。
		if decision.Finalizable {
			break
		}
		if h.tryAutoContinueAfterFinalization(taskCtx, conversationID, resultMA, decision, &finalizationAutoContinueAttempt, &segHistory, &segFinalMessage, progressCallback) {
			continue
		}
		break
	}

	if runErr != nil {
		h.handleBatchSubTaskRunError(queueID, task, conversationID, assistantMessageID, baseCtx, taskCtx, resultMA, runErr, &finishStatus)
		return
	}

	if resultMA == nil {
		h.logger.Error("批量任务执行成功但无结果对象",
			zap.String("queueId", queueID),
			zap.String("taskId", task.ID),
			zap.String("conversationId", conversationID))
		h.batchTaskManager.UpdateTaskStatus(queueID, task.ID, BatchTaskStatusFailed, "", "内部错误：无执行结果")
		return
	}

	decision = finalizationStoppedDecision(decision, &finalizationAutoContinueAttempt)
	decision = batchSubTaskDeliveryDecision(resultMA, decision)
	finishStatus = decision.Status
	errorMsg := ""
	if !decision.Finalizable {
		errorMsg = finalizationBlockedMessage(decision)
		h.logger.Info("批量任务执行已停止但未达到交付条件", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID), zap.String("status", finishStatus), zap.String("completionReason", decision.CompletionReason))
	} else {
		h.logger.Info("批量任务执行成功", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID))
	}

	resText := resultMA.Response
	mcpIDs := resultMA.MCPExecutionIDs
	lastIn := resultMA.LastAgentTraceInput
	lastOut := resultMA.LastAgentTraceOutput

	// 最终回复治理：候选文本必须先通过 finalizer 判定（decision 已在续跑循环内算出）。
	if !decision.Finalizable {
		resText = finalizationBlockedMessage(decision)
	}

	if assistantMessageID != "" {
		if !decision.Finalizable {
			_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", resText, time.Now(), assistantMessageID)
			_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "finalization_check", finalizationCheckMessage(decision), decision)
		} else if updateErr := h.db.UpdateAssistantMessageFinalize(assistantMessageID, resText, mcpIDs, multiagent.AggregatedReasoningFromTraceJSON(lastIn)); updateErr != nil {
			h.logger.Warn("更新助手消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(updateErr))
			if _, err = h.db.AddMessage(conversationID, "assistant", resText, mcpIDs); err != nil {
				h.logger.Error("保存助手消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID), zap.Error(err))
			}
		}
	} else if _, err = h.db.AddMessage(conversationID, "assistant", resText, mcpIDs); err != nil {
		h.logger.Error("保存助手消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID), zap.Error(err))
	}

	if lastIn != "" || lastOut != "" {
		if err := h.db.SaveAgentTrace(conversationID, lastIn, lastOut); err != nil {
			h.logger.Warn("保存代理轨迹失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(err))
		}
	}

	batchStatus := finishStatus
	if batchStatus == "timeout" {
		// 会话运行历史保留 timeout；批量项延续原有 failed 表示执行超时的约定。
		batchStatus = BatchTaskStatusFailed
	}
	h.batchTaskManager.UpdateTaskStatusWithConversationID(queueID, task.ID, batchStatus, resText, errorMsg, conversationID)
}

// batchSubTaskDeliveryDecision 将批量交付状态与 RunResult 对齐；nil runErr 不是成功凭据。
func batchSubTaskDeliveryDecision(result *multiagent.RunResult, decision agentfinalizer.Decision) agentfinalizer.Decision {
	if decision.Finalizable {
		decision.Status = BatchTaskStatusCompleted
	} else {
		decision.Finalized = false
		switch decision.Status {
		case BatchTaskStatusFailed, BatchTaskStatusCancelled, "timeout":
			// 保留显式的失败、取消和超时决策。
		default:
			decision.Status = BatchTaskStatusBlocked
		}
	}
	if result != nil {
		result.Status = decision.Status
		result.Finalized = decision.Finalized
		result.CompletionReason = decision.CompletionReason
		result.EvidenceVerified = decision.EvidenceVerified
		result.EvidenceRefs = append([]string(nil), decision.EvidenceRefs...)
		result.PendingExecutionIDs = append([]string(nil), decision.PendingExecutionIDs...)
		result.MissingChecks = append([]string(nil), decision.MissingChecks...)
	}
	return decision
}

// batchSubTaskDoneEvent 携带真实收尾状态及阻断详情，不能由 done 推断为成功。
func batchSubTaskDoneEvent(conversationID, finishStatus string, decision agentfinalizer.Decision) StreamEvent {
	if decision.Status != finishStatus {
		decision.CompletionReason = finishStatus
	}
	decision.Status = finishStatus
	if finishStatus != BatchTaskStatusCompleted {
		decision.Finalizable = false
		decision.Finalized = false
	}
	return StreamEvent{Type: "done", Data: finalizationResponsePayload(decision, map[string]interface{}{"conversationId": conversationID})}
}

func (h *AgentHandler) finishBatchSubTask(conversationID, finishStatus string, decision agentfinalizer.Decision) {
	if h.taskEventBus != nil {
		if b, err := json.Marshal(batchSubTaskDoneEvent(conversationID, finishStatus, decision)); err == nil {
			h.taskEventBus.Publish(conversationID, append(append([]byte("data: "), b...), '\n', '\n'))
		}
	}
	// FinishTask 会关闭事件流，因此必须在 done 发布后调用。
	h.tasks.FinishTask(conversationID, finishStatus)
}

func (h *AgentHandler) handleBatchSubTaskRunError(
	queueID string,
	task *BatchTask,
	conversationID, assistantMessageID string,
	baseCtx, taskCtx context.Context,
	resultMA *multiagent.RunResult,
	runErr error,
	finishStatus *string,
) {
	if shouldPersistEinoAgentTraceAfterRunError(baseCtx) {
		h.persistEinoAgentTraceForResume(conversationID, resultMA)
	}
	errStr := runErr.Error()
	partialResp := ""
	if resultMA != nil {
		partialResp = resultMA.Response
	}
	isCancelled := errors.Is(context.Cause(baseCtx), ErrTaskCancelled) ||
		errors.Is(runErr, context.Canceled) ||
		strings.Contains(strings.ToLower(errStr), "context canceled") ||
		strings.Contains(strings.ToLower(errStr), "context cancelled") ||
		(partialResp != "" && (strings.Contains(partialResp, "任务已被取消") || strings.Contains(partialResp, "任务执行中断")))
	isTimeout := errors.Is(runErr, context.DeadlineExceeded) || errors.Is(context.Cause(taskCtx), context.DeadlineExceeded)

	if isTimeout {
		*finishStatus = "timeout"
	} else if isCancelled {
		*finishStatus = "cancelled"
	} else {
		*finishStatus = "failed"
	}

	if isCancelled {
		h.logger.Info("批量任务被取消", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID))
		cancelMsg := "任务已被用户取消，后续操作已停止。"
		if partialResp != "" && (strings.Contains(partialResp, "任务已被取消") || strings.Contains(partialResp, "任务执行中断")) {
			cancelMsg = partialResp
		}
		if assistantMessageID != "" {
			if updateErr := h.appendAssistantMessageNotice(assistantMessageID, cancelMsg); updateErr != nil {
				h.logger.Warn("更新取消后的助手消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(updateErr))
			}
			if err := h.db.AddProcessDetail(assistantMessageID, conversationID, "cancelled", cancelMsg, nil); err != nil {
				h.logger.Warn("保存取消详情失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(err))
			}
		} else if _, errMsg := h.db.AddMessage(conversationID, "assistant", cancelMsg, nil); errMsg != nil {
			h.logger.Warn("保存取消消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(errMsg))
		}
		h.batchTaskManager.UpdateTaskStatusWithConversationID(queueID, task.ID, BatchTaskStatusCancelled, cancelMsg, "", conversationID)
		return
	}

	h.logger.Error("批量任务执行失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.String("conversationId", conversationID), zap.Error(runErr))
	errorMsg := runExecutionErrorMessage(runErr)
	if assistantMessageID != "" {
		if _, updateErr := h.db.Exec(
			"UPDATE messages SET content = ?, updated_at = ? WHERE id = ?",
			errorMsg,
			time.Now(), assistantMessageID,
		); updateErr != nil {
			h.logger.Warn("更新失败后的助手消息失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(updateErr))
		}
		if err := h.db.AddProcessDetail(assistantMessageID, conversationID, "error", errorMsg, nil); err != nil {
			h.logger.Warn("保存错误详情失败", zap.String("queueId", queueID), zap.String("taskId", task.ID), zap.Error(err))
		}
	}
	h.batchTaskManager.UpdateTaskStatus(queueID, task.ID, BatchTaskStatusFailed, "", runErr.Error())
}

func (h *AgentHandler) batchTaskRunConfig(channelID string) *config.Config {
	if h == nil || h.config == nil {
		return nil
	}
	channelID = strings.TrimSpace(channelID)
	if channelID == "" {
		return h.config
	}
	cfg, _, err := h.configForAIChannel(channelID)
	if err != nil || cfg == nil {
		if h.logger != nil {
			h.logger.Warn("批量任务指定模型通道不可用，改用默认通道", zap.String("aiChannelId", channelID), zap.Error(err))
		}
		return h.config
	}
	return cfg
}

func batchModelErrorShouldRetry(baseCtx, taskCtx context.Context, runErr error) bool {
	if runErr == nil {
		return false
	}
	if errors.Is(context.Cause(baseCtx), ErrTaskCancelled) {
		return false
	}
	if taskCtx != nil && taskCtx.Err() != nil {
		return false
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return false
	}
	return multiagent.IsModelInterruptError(runErr)
}

func (h *AgentHandler) waitBatchModelRetry(taskCtx context.Context, queueID string, task *BatchTask, conversationID, assistantMessageID string, attempt, maxRetry int, runErr error) bool {
	if task == nil || runErr == nil {
		return false
	}
	h.batchTaskManager.NoteTaskModelRetry(queueID, task.ID, attempt, runErr.Error())
	if assistantMessageID != "" && h.db != nil {
		note := fmt.Sprintf("模型报错，正在第 %d/%d 次自动重试…\n%s", attempt, maxRetry, runErr.Error())
		_, _ = h.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ?", note, time.Now(), assistantMessageID)
		_ = h.db.AddProcessDetail(assistantMessageID, conversationID, "retry", note, nil)
	}
	backoff := time.Duration(attempt) * 2 * time.Second
	if backoff > 12*time.Second {
		backoff = 12 * time.Second
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(backoff):
		return true
	}
}
