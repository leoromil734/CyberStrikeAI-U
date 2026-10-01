package handler

import (
	"strings"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// attachConversationAIModels 为对话列表批量附加「最近使用的 AI 通道/模型」，用于列表展示。
func attachConversationAIModels(db *database.DB, conversations []*database.Conversation) {
	if db == nil || len(conversations) == 0 {
		return
	}
	ids := make([]string, 0, len(conversations))
	for _, conv := range conversations {
		if conv != nil && strings.TrimSpace(conv.ID) != "" {
			ids = append(ids, conv.ID)
		}
	}
	models := db.GetConversationAIModels(ids)
	if len(models) == 0 {
		return
	}
	for _, conv := range conversations {
		if conv == nil {
			continue
		}
		if m, ok := models[strings.TrimSpace(conv.ID)]; ok {
			conv.AIChannelID = m.ChannelID
			conv.AIModel = m.Model
		}
	}
}

// attachAgentTaskAIModels uses each task's recorded run model rather than the
// current default/selected channel, which may differ across concurrent tasks.
// Call after access filtering and enrich only the task-list snapshots.
func attachAgentTaskAIModels(db *database.DB, tasks []*AgentTask) {
	if db == nil || len(tasks) == 0 {
		return
	}
	ids := make([]string, 0, len(tasks))
	for _, task := range tasks {
		if task != nil && strings.TrimSpace(task.ConversationID) != "" {
			ids = append(ids, task.ConversationID)
		}
	}
	models := db.GetConversationAIModels(ids)
	for _, task := range tasks {
		if task == nil {
			continue
		}
		if model, ok := models[strings.TrimSpace(task.ConversationID)]; ok {
			task.AIChannelID = model.ChannelID
			task.AIModel = model.Model
		}
	}
}

// recordConversationAIChannel 记录某对话最近一次运行使用的 AI 通道与模型名（对话列表展示用）。
// 传入的 channelID 允许为空（表示跟随默认通道），落库时用实际解析出的通道 ID 与模型名。
func (h *AgentHandler) recordConversationAIChannel(conversationID, channelID string) {
	if h == nil || h.db == nil {
		return
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return
	}
	resolvedID := strings.TrimSpace(channelID)
	model := ""
	if h.config != nil {
		if oa, id, ok := h.config.ResolveAIChannel(resolvedID); ok {
			resolvedID = strings.TrimSpace(id)
			model = strings.TrimSpace(oa.Model)
		}
	}
	if err := h.db.SetConversationAIChannel(conversationID, resolvedID, model); err != nil && h.logger != nil {
		// 只是列表展示信息，失败不影响本轮对话。
		h.logger.Debug("记录对话 AI 通道失败", zap.String("conversationId", conversationID), zap.Error(err))
	}
}
