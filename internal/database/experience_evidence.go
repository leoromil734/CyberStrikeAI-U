package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	em "cyberstrike-ai/internal/experience/model"
	"cyberstrike-ai/internal/mcp"
)

// ExperienceExecutionArchive is private evidence, not searchable memory content.
// Authorization is checked using both source ownership and current resource access.
type ExperienceExecutionArchive struct {
	Execution   *mcp.ToolExecution
	ProjectID   string
	ContentHash string
}

func archiveExperienceExecutionTx(tx *Tx, id string) error {
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM experience_execution_archives WHERE execution_id = ?`, id).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	var e mcp.ToolExecution
	var args string
	var result, errorText sql.NullString
	var end sql.NullTime
	err := tx.QueryRow(`SELECT id, tool_name, arguments, status, result, error, start_time, end_time,
	 COALESCE(owner_user_id,''), COALESCE(conversation_id,'') FROM tool_executions WHERE id = ?`, id).Scan(&e.ID, &e.ToolName, &args, &e.Status, &result, &errorText, &e.StartTime, &end, &e.OwnerUserID, &e.ConversationID)
	if err != nil {
		return err
	}
	if !end.Valid {
		return fmt.Errorf("experience evidence is not terminal")
	}
	e.EndTime = &end.Time
	e.Error = errorText.String
	if err := json.Unmarshal([]byte(args), &e.Arguments); err != nil {
		return err
	}
	if result.Valid {
		if err := json.Unmarshal([]byte(result.String), &e.Result); err != nil {
			return err
		}
	}
	var project sql.NullString
	if e.ConversationID != "" {
		if err := tx.QueryRow(`SELECT project_id FROM conversations WHERE id = ?`, e.ConversationID).Scan(&project); err != nil && err != sql.ErrNoRows {
			return err
		}
	}
	b, err := json.Marshal(struct {
		Execution   mcp.ToolExecution `json:"execution"`
		OwnerUserID string            `json:"owner_user_id"`
	}{Execution: e, OwnerUserID: e.OwnerUserID})
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO experience_execution_archives (execution_id, owner_user_id, conversation_id, project_id, snapshot_json, content_hash, archived_at)
	 VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(execution_id) DO NOTHING`, id, e.OwnerUserID, e.ConversationID, project.String, string(b), em.Hash(b), time.Now().UTC())
	return err
}

func (db *DB) GetExperienceExecutionArchive(id string) (*ExperienceExecutionArchive, error) {
	var raw, owner, conversation, project, hash string
	if err := db.QueryRow(`SELECT snapshot_json, owner_user_id, conversation_id, project_id, content_hash FROM experience_execution_archives WHERE execution_id = ?`, id).Scan(&raw, &owner, &conversation, &project, &hash); err != nil {
		return nil, err
	}
	if em.Hash([]byte(raw)) != hash {
		return nil, fmt.Errorf("experience evidence integrity check failed")
	}
	var payload struct {
		Execution   mcp.ToolExecution `json:"execution"`
		OwnerUserID string            `json:"owner_user_id"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	e := payload.Execution
	if e.ID != id || payload.OwnerUserID != owner || e.ConversationID != conversation {
		return nil, fmt.Errorf("experience evidence metadata mismatch")
	}
	e.OwnerUserID = owner
	return &ExperienceExecutionArchive{Execution: &e, ProjectID: project, ContentHash: hash}, nil
}

func (db *DB) ExperienceEvidenceContains(id string, revision int, executionID string) bool {
	var count int
	return db.QueryRow(`SELECT COUNT(*) FROM experience_evidence WHERE entry_id = ? AND revision = ? AND execution_id = ?`, id, revision, executionID).Scan(&count) == nil && count > 0
}
