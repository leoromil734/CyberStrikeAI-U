package database

import (
	"context"
	"cyberstrike-ai/internal/evidence"
	"fmt"
	"time"
)

func (db *DB) initResultIngestionTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS result_ingestion_jobs (
 execution_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,conversation_id TEXT NOT NULL,owner TEXT NOT NULL,
 assessment_id TEXT NOT NULL,scope_id TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',updated_at_ms BIGINT NOT NULL)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_result_ingestion_partition ON result_ingestion_jobs(project_id,conversation_id,assessment_id,state)`)
	return err
}

func (db *DB) SetResultIngestionState(ctx context.Context, e evidence.Execution, state, reason string) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	switch state {
	case "pending", "complete", "partial", "failed":
	default:
		return fmt.Errorf("invalid result ingestion state")
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	result, err := db.ExecContext(ctx, `INSERT INTO result_ingestion_jobs(execution_id,project_id,conversation_id,owner,assessment_id,scope_id,state,reason,updated_at_ms)
 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(execution_id) DO UPDATE SET state=excluded.state,reason=excluded.reason,updated_at_ms=excluded.updated_at_ms
 WHERE result_ingestion_jobs.project_id=excluded.project_id AND result_ingestion_jobs.conversation_id=excluded.conversation_id
 AND result_ingestion_jobs.owner=excluded.owner AND result_ingestion_jobs.assessment_id=excluded.assessment_id AND result_ingestion_jobs.scope_id=excluded.scope_id`,
		e.ID, e.ProjectID, e.ConversationID, e.Owner, e.AssessmentID, e.ScopeID, state, reason, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return evidence.ErrDenied
	}
	return err
}

type ResultIngestionState struct {
	ExecutionID string `json:"execution_id"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
}

func (db *DB) ResultIngestionStates(projectID, conversationID, assessmentID string) ([]ResultIngestionState, error) {
	rows, err := db.Query(`SELECT execution_id,state,reason FROM result_ingestion_jobs WHERE project_id=? AND conversation_id=? AND assessment_id=? ORDER BY updated_at_ms`, projectID, conversationID, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResultIngestionState{}
	for rows.Next() {
		var r ResultIngestionState
		if err := rows.Scan(&r.ExecutionID, &r.State, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Interrupted ingestion remains an explicit gap after a process restart.
func (db *DB) ReconcileResultIngestionJobs() error {
	_, err := db.Exec(`UPDATE result_ingestion_jobs SET state='failed',reason='ingestion interrupted by process restart; original must be reimported',updated_at_ms=? WHERE state='pending'`, time.Now().UnixMilli())
	return err
}
