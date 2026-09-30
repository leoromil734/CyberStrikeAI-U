package handler

import (
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

// restoreUserConstraintsAfterCompaction only runs when a saved host ledger was
// removed with the old system prompt. Rebuild from original database user rows;
// never replay an old system instruction or a tool's imitation of a ledger.
func (h *AgentHandler) restoreUserConstraintsAfterCompaction(conversationID string, trace []map[string]interface{}, history []agent.ChatMessage) []agent.ChatMessage {
	if h == nil || h.db == nil {
		return history
	}
	compacted := false
	for _, msg := range trace {
		role, _ := msg["role"].(string)
		content, _ := msg["content"].(string)
		if role == "system" && strings.Contains(content, "<original_user_intent_ledger>") {
			compacted = true
			break
		}
	}
	if !compacted {
		return history
	}
	rows, err := h.db.Query(`SELECT content FROM messages WHERE conversation_id = ? AND role = 'user' ORDER BY created_at, id`, conversationID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("恢复原始用户约束失败", zap.Error(err))
		}
		return history
	}
	defer rows.Close()
	var originals []string
	for rows.Next() {
		var content string
		if err := rows.Scan(&content); err != nil {
			return history
		}
		originals = append(originals, content)
	}
	if err := rows.Err(); err != nil {
		return history
	}
	maxRunes, entryMaxRunes := config.DefaultSummarizationUserIntentLedgerMaxRunes, config.DefaultSummarizationUserIntentLedgerEntryMaxRunes
	if h.config != nil {
		maxRunes = h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunesEffective()
		entryMaxRunes = h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunesEffective()
	}
	ledger := multiagent.OriginalUserIntentLedgerForResume(originals, maxRunes, entryMaxRunes)
	if ledger == "" {
		return history
	}
	out := make([]agent.ChatMessage, 0, len(history)+1)
	out = append(out, agent.ChatMessage{Role: "user", Content: ledger, ModelFacingTrace: true})
	return append(out, history...)
}
