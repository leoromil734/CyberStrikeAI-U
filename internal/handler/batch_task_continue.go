package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

// batchTaskForConversationAction checks both permission-specific scopes. A
// global tasks permission must never grant access to an unrelated conversation.
func (h *AgentHandler) batchTaskForConversationAction(c *gin.Context, write bool) (*BatchTaskQueue, *BatchTask, bool) {
	action := "read"
	if write {
		action = "write"
	}
	session, ok := security.CurrentSession(c)
	for _, permission := range []string{"tasks:" + action, "chat:" + action} {
		if !ok || !session.Permissions[permission] {
			c.JSON(http.StatusForbidden, gin.H{"error": "权限不足", "permission": permission})
			return nil, nil, false
		}
	}
	if h.db == nil || h.batchTaskManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "任务服务不可用"})
		return nil, nil, false
	}
	queueID, taskID := strings.TrimSpace(c.Param("queueId")), strings.TrimSpace(c.Param("taskId"))
	if queueID == "" || taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "queueId 和 taskId 不能为空"})
		return nil, nil, false
	}
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("tasks:"+action), "batch_task", queueID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该资源"})
		return nil, nil, false
	}
	queue, exists := h.batchTaskManager.GetBatchQueue(queueID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "队列不存在"})
		return nil, nil, false
	}
	for _, task := range queue.Tasks {
		if task == nil || task.ID != taskID {
			continue
		}
		if id := strings.TrimSpace(task.ConversationID); id != "" &&
			!h.db.UserCanAccessResource(session.UserID, session.ScopeFor("chat:"+action), "conversation", id) {
			// Do not reveal the conversation ID, text, or running state on denial.
			c.JSON(http.StatusForbidden, gin.H{"error": "无权访问该资源"})
			return nil, nil, false
		}
		return queue, task, true
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "任务不存在"})
	return nil, nil, false
}

// GetBatchTaskOriginalMessage returns a small, read-only payload. The task text
// is a fallback only when no conversation was ever linked, not on lookup errors.
func (h *AgentHandler) GetBatchTaskOriginalMessage(c *gin.Context) {
	_, task, ok := h.batchTaskForConversationAction(c, false)
	if !ok {
		return
	}
	if strings.TrimSpace(task.ConversationID) == "" {
		c.JSON(http.StatusOK, gin.H{"message": task.Message, "source": "task"})
		return
	}
	message, err := h.db.GetFirstConversationUserMessage(task.ConversationID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "原会话中没有可读取的初始用户消息"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取原始消息失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": message, "source": "conversation"})
}

func assessmentModeRequirements(mode string) (execution, coverage bool) {
	return mode == database.AssessmentModeExecution || mode == database.AssessmentModeComprehensive,
		mode == database.AssessmentModeComprehensive
}

func (h *AgentHandler) prepareBatchTaskContinuation(c *gin.Context) (*ChatRequest, string, bool) {
	queue, task, ok := h.batchTaskForConversationAction(c, true)
	if !ok {
		return nil, "", false
	}
	conversationID := strings.TrimSpace(task.ConversationID)
	if conversationID == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "任务没有原会话，无法继续；请使用执行入口", "errorType": "missing_conversation"})
		return nil, "", false
	}
	if h.tasks == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "任务服务不可用"})
		return nil, "", false
	}
	if queue.Status == BatchQueueStatusRunning || queueHasRunningTaskLocked(queue) || h.batchTaskManager.IsQueueExecutorActive(queue.ID) {
		c.JSON(http.StatusConflict, gin.H{"error": "队列正在执行或收尾，请稍后继续", "errorType": "queue_active"})
		return nil, "", false
	}
	if h.tasks.GetTask(conversationID) != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "当前会话已有任务正在执行或停止中", "errorType": "task_already_running"})
		return nil, "", false
	}
	meta, err := h.db.GetConversationContinuationMetadata(conversationID)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "原会话不存在"})
		return nil, "", false
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取原会话配置失败"})
		return nil, "", false
	}
	req := &ChatRequest{
		Message: "继续", ConversationID: conversationID, Role: queue.Role,
		ProjectID: meta.ProjectID, AIChannelID: strings.TrimSpace(task.AIChannelID),
	}
	if channel := strings.TrimSpace(meta.AIChannelID); channel != "" {
		req.AIChannelID = channel
	}
	runCfg, _, err := h.configForAIChannel(req.AIChannelID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, "", false
	}
	// A renamed/deleted/reconfigured channel must not silently change the model
	// under a one-click continuation. Legacy conversations may lack this field.
	if meta.AIModel != "" && strings.TrimSpace(meta.AIModel) != strings.TrimSpace(runCfg.OpenAI.Model) {
		c.JSON(http.StatusConflict, gin.H{"error": "原会话模型配置已改变，请恢复原模型后继续", "errorType": "original_model_unavailable"})
		return nil, "", false
	}
	mode := config.NormalizeAgentMode(queue.AgentMode)
	if mode != "eino_single" {
		if !runCfg.MultiAgent.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "原任务的多代理模式未启用"})
			return nil, "", false
		}
		req.Orchestration = mode
	}
	requireExecution, requireCoverage := assessmentModeRequirements(queue.AssessmentMode)
	previous, err := h.db.LatestAssessmentRun(conversationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取原会话评估策略失败"})
		return nil, "", false
	}
	if previous != nil {
		execution, coverage := assessmentModeRequirements(previous.Mode)
		requireExecution = requireExecution || execution
		requireCoverage = requireCoverage || coverage
	}
	req.Finalization = ChatFinalizationRequest{
		RequireExecutionEvidence: &requireExecution, RequireCoverageEvidence: &requireCoverage,
	}
	return req, mode, true
}

// ContinueBatchTask sends exactly “继续” through the existing detached SSE run
// path. It never resets/re-writes the queue or task snapshot, creates a replacement
// conversation, or trusts client-supplied role/model/message/finalization fields.
// The client may detach only after the stream's task_started acknowledgement.
func (h *AgentHandler) ContinueBatchTask(c *gin.Context) {
	req, mode, ok := h.prepareBatchTaskContinuation(c)
	if !ok {
		return
	}
	body, err := json.Marshal(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "构建继续请求失败"})
		return
	}
	original := c.Request
	c.Request = original.Clone(original.Context())
	defer func() { c.Request = original }()
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	c.Request.GetBody = nil
	c.Request.Header.Set("Content-Type", "application/json")
	if mode == "eino_single" {
		h.EinoSingleAgentLoopStream(c)
	} else {
		h.MultiAgentLoopStream(c)
	}
}
