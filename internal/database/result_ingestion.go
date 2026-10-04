package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"cyberstrike-ai/internal/evidence"
	"github.com/google/uuid"
)

const ResultIngestionMaxAttempts = 5

var ErrResultIngestionLeaseLost = errors.New("result ingestion lease lost")

func (db *DB) initResultIngestionTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS result_ingestion_jobs (
 execution_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,conversation_id TEXT NOT NULL,owner TEXT NOT NULL,
 assessment_id TEXT NOT NULL,scope_id TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',updated_at_ms BIGINT NOT NULL)`)
	if err != nil {
		return err
	}
	// Additive migration: old pending rows are immediately eligible; historical
	// failed rows stay failed until an operator explicitly selects their IDs.
	for _, c := range []struct{ name, definition string }{
		{"attempts", "INTEGER NOT NULL DEFAULT 0"},
		{"total_attempts", "INTEGER NOT NULL DEFAULT 0"},
		{"next_attempt_ms", "BIGINT NOT NULL DEFAULT 0"},
		{"lease_until_ms", "BIGINT NOT NULL DEFAULT 0"},
		{"lease_token", "TEXT NOT NULL DEFAULT ''"},
		{"last_error", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := db.addColumnIfMissing("result_ingestion_jobs", c.name, "ALTER TABLE result_ingestion_jobs ADD COLUMN "+c.name+" "+c.definition); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_result_ingestion_partition ON result_ingestion_jobs(project_id,conversation_id,assessment_id,state)`,
		`CREATE INDEX IF NOT EXISTS idx_result_ingestion_due ON result_ingestion_jobs(state,next_attempt_ms,lease_until_ms)`,
		`CREATE TABLE IF NOT EXISTS result_ingestion_snapshots (execution_id TEXT PRIMARY KEY,snapshot_json TEXT NOT NULL,sha256 TEXT NOT NULL)`,
	} {
		if _, err = db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

// InitResultIngestionTables also supports standalone offline recovery commands.
func (db *DB) InitResultIngestionTables() error { return db.initResultIngestionTables() }

func ingestionReason(reason string) string {
	runes := []rune(toolExecutionText(reason))
	if len(runes) > 1024 {
		runes = runes[:1024]
	}
	return string(runes)
}

// SetResultIngestionState is retained for explicit artifact registration. It
// cannot steal a pending durable job or overwrite a worker's active lease.
// Queue workers must use FinishResultIngestion with their fencing token.
func (db *DB) SetResultIngestionState(ctx context.Context, e evidence.Execution, state, reason string) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	switch state {
	case "pending", "complete", "partial", "failed":
	default:
		return fmt.Errorf("invalid result ingestion state")
	}
	result, err := db.ExecContext(ctx, `INSERT INTO result_ingestion_jobs(execution_id,project_id,conversation_id,owner,assessment_id,scope_id,state,reason,updated_at_ms)
 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(execution_id) DO UPDATE SET state=excluded.state,reason=excluded.reason,updated_at_ms=excluded.updated_at_ms
 WHERE result_ingestion_jobs.project_id=excluded.project_id AND result_ingestion_jobs.conversation_id=excluded.conversation_id
 AND result_ingestion_jobs.owner=excluded.owner AND result_ingestion_jobs.assessment_id=excluded.assessment_id AND result_ingestion_jobs.scope_id=excluded.scope_id
 AND result_ingestion_jobs.lease_token=''
 AND NOT (result_ingestion_jobs.state='pending' AND EXISTS (SELECT 1 FROM result_ingestion_snapshots s WHERE s.execution_id=excluded.execution_id))`,
		e.ID, e.ProjectID, e.ConversationID, e.Owner, e.AssessmentID, e.ScopeID, state, ingestionReason(reason), time.Now().UnixMilli())
	return ingestionAffected(result, err, evidence.ErrDenied)
}

func ingestionAffected(result sql.Result, err, missing error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return missing
	}
	return err
}

type ResultIngestionState struct {
	ExecutionID string `json:"execution_id"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
}

// ResultIngestionJob contains metadata only, never raw tool output. Pending also
// includes leased/running and delayed-retry jobs, for existing coverage readers.
type ResultIngestionJob struct {
	ResultIngestionState
	evidence.Access
	AssessmentID  string `json:"assessment_id"`
	ScopeID       string `json:"scope_id"`
	Attempts      int    `json:"attempts"`
	TotalAttempts int    `json:"total_attempts"`
	NextAttemptMS int64  `json:"next_attempt_ms"`
	LeaseUntilMS  int64  `json:"lease_until_ms"`
	LeaseToken    string `json:"-"`
	LastError     string `json:"last_error,omitempty"`
}

const ingestionJobColumns = `execution_id,state,reason,project_id,conversation_id,owner,assessment_id,scope_id,attempts,total_attempts,next_attempt_ms,lease_until_ms,lease_token,last_error`

func scanIngestionJob(row resultScanner) (ResultIngestionJob, error) {
	var j ResultIngestionJob
	err := row.Scan(&j.ExecutionID, &j.State, &j.Reason, &j.ProjectID, &j.ConversationID, &j.Owner, &j.AssessmentID, &j.ScopeID, &j.Attempts, &j.TotalAttempts, &j.NextAttemptMS, &j.LeaseUntilMS, &j.LeaseToken, &j.LastError)
	return j, err
}

// ResultIngestionJob is a maintenance API; callers must not expose it directly
// through an unauthenticated transport. Application evidence APIs remain scoped.
func (db *DB) ResultIngestionJob(ctx context.Context, id string) (ResultIngestionJob, error) {
	return scanIngestionJob(db.QueryRowContext(ctx, `SELECT `+ingestionJobColumns+` FROM result_ingestion_jobs WHERE execution_id=?`, id))
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

const reconcileResultIngestionSQL = `UPDATE result_ingestion_jobs SET state='failed',reason=?,updated_at_ms=?,lease_token='',lease_until_ms=0
 WHERE state='pending' AND attempts>=5 AND lease_until_ms<=?`

// ReconcileResultIngestionJobs never invalidates live leases or requeues historical
// failures. A restart recovers pending work through normal atomic claiming.
func (db *DB) ReconcileResultIngestionJobs() error {
	return db.reconcileResultIngestions(context.Background(), "")
}

func (db *DB) reconcileResultIngestions(ctx context.Context, id string) error {
	now := time.Now().UnixMilli()
	query := reconcileResultIngestionSQL
	args := []interface{}{"ingestion lease expired after maximum attempts; explicit replay required", now, now}
	if id != "" {
		query += ` AND execution_id=?`
		args = append(args, id)
	}
	_, err := db.ExecContext(ctx, query, args...)
	return err
}

// ClaimResultIngestion atomically claims one due row. id="" is for the normal
// worker; recovery must pass an explicit ID. Rechecking eligibility in the outer
// UPDATE makes the statement safe on both PostgreSQL and SQLite when two workers
// selected the same candidate. No SELECT-then-unconditional-UPDATE race exists.
func (db *DB) ClaimResultIngestion(ctx context.Context, id string, lease time.Duration) (*ResultIngestionJob, error) {
	if lease < time.Second || lease > 10*time.Minute {
		return nil, fmt.Errorf("invalid ingestion lease duration")
	}
	if err := db.reconcileResultIngestions(ctx, id); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	eligible := `state='pending' AND attempts<5 AND next_attempt_ms<=? AND lease_until_ms<=?`
	query := `UPDATE result_ingestion_jobs SET attempts=attempts+1,total_attempts=total_attempts+1,lease_token=?,lease_until_ms=?,updated_at_ms=?
 WHERE execution_id=(SELECT execution_id FROM result_ingestion_jobs WHERE ` + eligible
	args := []interface{}{uuid.NewString(), now + lease.Milliseconds(), now, now, now}
	if id != "" {
		query += ` AND execution_id=?`
		args = append(args, id)
	}
	query += ` ORDER BY next_attempt_ms,updated_at_ms,execution_id LIMIT 1) AND ` + eligible + ` RETURNING ` + ingestionJobColumns
	args = append(args, now, now)
	job, err := scanIngestionJob(db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

const ingestionLeaseWhere = `execution_id=? AND project_id=? AND conversation_id=? AND owner=? AND assessment_id=? AND scope_id=? AND state='pending' AND attempts=? AND lease_token=? AND lease_until_ms>?`

func ingestionLeaseArgs(j ResultIngestionJob) []interface{} {
	return []interface{}{j.ExecutionID, j.ProjectID, j.ConversationID, j.Owner, j.AssessmentID, j.ScopeID, j.Attempts, j.LeaseToken, time.Now().UnixMilli()}
}

func (db *DB) CheckResultIngestionLease(ctx context.Context, j ResultIngestionJob) error {
	if j.LeaseToken == "" {
		return ErrResultIngestionLeaseLost
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM result_ingestion_jobs WHERE `+ingestionLeaseWhere, ingestionLeaseArgs(j)...).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return ErrResultIngestionLeaseLost
	}
	return nil
}

func (db *DB) RenewResultIngestionLease(ctx context.Context, j ResultIngestionJob, lease time.Duration) error {
	if j.LeaseToken == "" || lease < time.Second || lease > 10*time.Minute {
		return ErrResultIngestionLeaseLost
	}
	args := append([]interface{}{time.Now().Add(lease).UnixMilli()}, ingestionLeaseArgs(j)...)
	result, err := db.ExecContext(ctx, `UPDATE result_ingestion_jobs SET lease_until_ms=? WHERE `+ingestionLeaseWhere, args...)
	return ingestionAffected(result, err, ErrResultIngestionLeaseLost)
}

func ResultIngestionRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 5 {
		attempt = 5
	}
	delay := time.Second * time.Duration(1<<uint(attempt))
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

// FinishResultIngestion fences every completion/retry with the claim's binding,
// attempt and random token, including its expiry. Failed attempts are retried
// with capped exponential backoff, then retained as diagnostic terminal failures.
func (db *DB) FinishResultIngestion(ctx context.Context, j ResultIngestionJob, state, reason string, retryable bool) error {
	if j.LeaseToken == "" {
		return ErrResultIngestionLeaseLost
	}
	if state != "complete" && state != "partial" && state != "failed" {
		return fmt.Errorf("invalid ingestion terminal state")
	}
	now := time.Now()
	next := int64(0)
	lastError := j.LastError
	if state == "failed" {
		lastError = ingestionReason(reason)
		if retryable && j.Attempts < ResultIngestionMaxAttempts {
			state = "pending"
			next = now.Add(ResultIngestionRetryDelay(j.Attempts)).UnixMilli()
		}
	}
	args := append([]interface{}{state, ingestionReason(reason), lastError, next, now.UnixMilli()}, ingestionLeaseArgs(j)...)
	result, err := db.ExecContext(ctx, `UPDATE result_ingestion_jobs SET state=?,reason=?,last_error=?,next_attempt_ms=?,updated_at_ms=?,lease_token='',lease_until_ms=0 WHERE `+ingestionLeaseWhere, args...)
	return ingestionAffected(result, err, ErrResultIngestionLeaseLost)
}

// RequeueResultIngestion retries one explicitly selected failed/partial job. It
// does not touch successful or active work, change binding, erase last_error, or
// claim success. Attempts reset for this replay; total_attempts never resets.
func (db *DB) RequeueResultIngestion(ctx context.Context, e evidence.Execution) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	stored, err := db.ResultExecution(ctx, e.ID)
	if err != nil {
		return err
	}
	if !sameIngestionBinding(stored, e) {
		return evidence.ErrDenied
	}
	result, err := db.ExecContext(ctx, `UPDATE result_ingestion_jobs SET state='pending',last_error=CASE WHEN reason<>'' THEN reason ELSE last_error END,
 reason='explicit offline replay requested',attempts=0,next_attempt_ms=0,lease_until_ms=0,lease_token='',updated_at_ms=?
 WHERE execution_id=? AND project_id=? AND conversation_id=? AND owner=? AND assessment_id=? AND scope_id=? AND state IN ('failed','partial') AND lease_token=''`,
		time.Now().UnixMilli(), e.ID, e.ProjectID, e.ConversationID, e.Owner, e.AssessmentID, e.ScopeID)
	return ingestionAffected(result, err, evidence.ErrDenied)
}
