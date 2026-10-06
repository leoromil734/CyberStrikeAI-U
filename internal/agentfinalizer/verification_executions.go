package agentfinalizer

import (
	"strings"

	"cyberstrike-ai/internal/database"
)

// bookkeepingToolNames never renew a stalled assessment. Completing one of
// these is a ledger or file read, not a new vulnerability check.
var bookkeepingToolNames = []string{
	"upsert_project_fact",
	"get_project_fact",
	"list_project_facts",
	"search_project_facts",
	"query_recon_inventory",
	"list_result_artifacts",
	"read_result_artifact",
	"register_result_artifact",
	"get_tool_execution",
	"cancel_tool_execution",
	"list_vulnerabilities",
	"eino_fs::read_file",
	"eino_fs::grep",
	"eino_fs::ls",
	"eino_fs::write_file",
}

func countVerificationExecutions(db *database.DB, conversationID string) int {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return 0
	}
	args := make([]interface{}, 0, 1+len(bookkeepingToolNames))
	args = append(args, conversationID)
	placeholders := make([]string, len(bookkeepingToolNames))
	for i, name := range bookkeepingToolNames {
		placeholders[i] = "?"
		args = append(args, name)
	}
	query := `SELECT COUNT(*) FROM tool_executions WHERE conversation_id = ? AND status = 'completed' AND tool_name NOT IN (` + strings.Join(placeholders, ",") + `)`
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}
