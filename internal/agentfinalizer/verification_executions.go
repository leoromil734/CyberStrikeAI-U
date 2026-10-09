package agentfinalizer

import (
	"strings"

	"cyberstrike-ai/internal/database"
)

// verificationToolNames are the only completed runs that renew a stalled
// assessment. Walking every URL or writing a fact is not one of them.
// record_vulnerability is deliberately absent: a completed recording run only
// renews continuation when it persists a NEW finding (countRecordedVulnerabilities).
// Otherwise re-recording an existing title+target could renew work forever.
var verificationToolNames = []string{
	"sqlmap",
	"nuclei",
	"dalfox",
	"ffuf",
	"dirsearch",
	"graphql-scanner",
	"jwt-analyzer",
	"interactsh-client",
	"dnslog",
}

func countVerificationExecutions(db *database.DB, conversationID string) int {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return 0
	}
	args := make([]interface{}, 0, 1+len(verificationToolNames))
	args = append(args, conversationID)
	placeholders := make([]string, len(verificationToolNames))
	for i, name := range verificationToolNames {
		placeholders[i] = "?"
		args = append(args, name)
	}
	query := `SELECT COUNT(*) FROM tool_executions WHERE conversation_id = ? AND status = 'completed' AND tool_name IN (` + strings.Join(placeholders, ",") + `)`
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

// countRecordedVulnerabilities counts persisted formal vulnerability records in
// this conversation. Only a NEW record renews a stalled assessment; re-recording
// an existing title+target is de-duplicated by the recording tool and cannot
// renew. Legacy duplicate rows only raise the baseline high-water mark.
func countRecordedVulnerabilities(db *database.DB, conversationID string) int {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return 0
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE conversation_id = ?`, conversationID).Scan(&n); err != nil {
		return 0
	}
	return n
}
