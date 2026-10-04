package agentfinalizer

import (
	"sort"

	"cyberstrike-ai/internal/database"
)

// Include detached/prior-segment executions, not only the final model segment's
// tool IDs. A failed status read must never turn running work into success.
func pendingConversationExecutions(db *database.DB, conversationID string, ids []string) ([]string, error) {
	pending := pendingExecutions(db, ids)
	if db == nil || conversationID == "" {
		return pending, nil
	}
	rows, err := db.Query(`SELECT id FROM tool_executions WHERE conversation_id = ? AND status IN ('queued', 'running')`, conversationID)
	if err != nil {
		return pending, err
	}
	defer rows.Close()
	seen := make(map[string]bool, len(pending))
	for _, id := range pending {
		seen[id] = true
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return pending, err
		}
		if !seen[id] {
			seen[id] = true
			pending = append(pending, id)
		}
	}
	sort.Strings(pending)
	return pending, rows.Err()
}
