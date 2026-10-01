package handler

import (
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/audit"
)

func (m *BatchTaskManager) persistQueuePause(queueID string, runningIDs []string) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE batch_task_queues SET status = ? WHERE id = ?", BatchQueueStatusPaused, queueID); err != nil {
		return err
	}
	query := "UPDATE batch_tasks SET status = ?, completed_at = NULL WHERE queue_id = ? AND (status = ?"
	args := []interface{}{BatchTaskStatusPaused, queueID, BatchTaskStatusRunning}
	if len(runningIDs) > 0 {
		query += " OR id IN (" + strings.TrimRight(strings.Repeat("?,", len(runningIDs)), ",") + ")"
		for _, id := range runningIDs {
			args = append(args, id)
		}
	}
	query += ")"
	if _, err := tx.Exec(query, args...); err != nil {
		return err
	}
	return tx.Commit()
}

func (h *AgentHandler) prepareBatchSubTaskConversation(queue *BatchTaskQueue, task *BatchTask, ownerID, scope, projectID string) (string, []agent.ChatMessage, bool, error) {
	if task.ResumeFromPause && strings.TrimSpace(task.ConversationID) != "" {
		id := strings.TrimSpace(task.ConversationID)
		oldProject, err := h.db.GetConversationProjectID(id)
		if err != nil || !h.db.UserCanAccessResource(ownerID, scope, "conversation", id) {
			return "", nil, false, fmt.Errorf("暂停会话不存在或不可访问，请显式单条重跑")
		}
		if queue.IndependentProjects && oldProject != projectID {
			return "", nil, false, fmt.Errorf("暂停会话与任务独立项目不一致，未复用旧目标上下文")
		}
		history, traceErr := h.loadHistoryFromAgentTrace(id)
		if traceErr != nil {
			messages, err := h.db.GetMessages(id)
			if err != nil {
				return "", nil, false, fmt.Errorf("读取暂停会话失败: %w", err)
			}
			history = dbMessagesToAgentChatMessages(messages)
		}
		return id, history, true, nil
	}
	meta := audit.ConversationCreateMeta("batch_task")
	meta.ProjectID = projectID
	conversation, err := h.db.CreateConversation(safeTruncateString(task.Message, 50), meta)
	if err != nil {
		return "", nil, false, fmt.Errorf("创建对话失败: %w", err)
	}
	if err := h.db.SetResourceOwner("conversation", conversation.ID, ownerID); err != nil {
		return "", nil, false, fmt.Errorf("设置对话归属失败: %w", err)
	}
	if err := h.db.AssignResourceToUser(ownerID, "conversation", conversation.ID); err != nil {
		return "", nil, false, fmt.Errorf("分配对话权限失败: %w", err)
	}
	return conversation.ID, nil, false, nil
}

// HasResumableTasks distinguishes a real continuation from a paused queue
// containing only permanent cancellations/failures/completed deliveries.
func (m *BatchTaskManager) HasResumableTasks(queueID string) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()
	queue, exists := m.loadedQueue(queueID)
	if !exists || queue == nil {
		return false
	}
	for _, task := range queue.Tasks {
		if task != nil && (task.Status == BatchTaskStatusPending || task.Status == BatchTaskStatusPaused) {
			return true
		}
	}
	return false
}
