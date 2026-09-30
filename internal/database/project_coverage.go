package database

// ListProjectCoverageFacts reads only the current conversation's recon ledger.
// Finalization must not load unrelated findings/POCs or another conversation's
// potentially large evidence bodies just to inspect coverage state.
func (db *DB) ListProjectCoverageFacts(projectID, conversationID string) ([]*ProjectFact, error) {
	rows, err := db.Query(`SELECT id, project_id, fact_key, category, summary, COALESCE(body,''), confidence,
		COALESCE(source_conversation_id,''), COALESCE(source_message_id,''), pinned,
		COALESCE(related_vulnerability_id,''), created_at, updated_at
		FROM project_facts WHERE project_id = ? AND source_conversation_id = ?
		AND confidence != 'deprecated' AND fact_key LIKE 'recon/%'
		ORDER BY updated_at DESC, fact_key`, projectID, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProjectFacts(rows)
}
