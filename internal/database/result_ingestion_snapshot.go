package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
)

func sameIngestionBinding(a, b evidence.Execution) bool {
	return a.ID == b.ID && a.Access == b.Access && a.AssessmentID == b.AssessmentID && a.ScopeID == b.ScopeID &&
		a.Tool == b.Tool && a.ParserTool == b.ParserTool && resultMillis(a.StartedAt) == resultMillis(b.StartedAt)
}

func validateIngestionOriginal(e evidence.Execution, original *mcp.ToolExecution) error {
	if original == nil || original.ID != e.ID || original.OwnerUserID != e.Owner || original.ConversationID != e.ConversationID || original.ToolName != e.Tool ||
		original.EndTime == nil || resultMillis(original.StartTime) != resultMillis(e.StartedAt) || resultMillis(*original.EndTime) != resultMillis(e.FinishedAt) || original.Status != e.Status {
		return fmt.Errorf("saved result does not match immutable execution binding: %w", evidence.ErrDenied)
	}
	switch original.Status {
	case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning, "":
		return fmt.Errorf("result is not terminal: %w", evidence.ErrDenied)
	}
	return nil
}

func ingestionSnapshotJSON(s ResultIngestionSnapshot) (string, string, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(body)
	return string(body), hex.EncodeToString(sum[:]), nil
}

// PersistResultIngestion is the synchronous terminal observer seam. Raw result,
// execution binding, immutable replay snapshot and pending marker commit in one
// transaction BEFORE a worker can claim the row. Only disk stores queued bodies;
// no channel or goroutine retains a backlog of ToolExecution values.
func (db *DB) PersistResultIngestion(ctx context.Context, e evidence.Execution, original *mcp.ToolExecution, projection ResultIngestionProjection) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	if err := validateIngestionOriginal(e, original); err != nil {
		return err
	}
	if projection.Owner != "" && projection.Owner != e.Owner {
		return evidence.ErrDenied
	}
	args, err := json.Marshal(original.Arguments)
	if err != nil {
		return err
	}
	var resultJSON sql.NullString
	copyOriginal := *original
	if original.Result != nil {
		result, err := marshalToolExecutionResult(original.Result)
		if err != nil {
			return err
		}
		resultJSON = sql.NullString{String: string(result), Valid: true}
		// Match PostgreSQL-safe persisted text, not a lossy runtime-only variant.
		copyOriginal.Result = nil
		if err = json.Unmarshal(result, &copyOriginal.Result); err != nil {
			return err
		}
	}
	copyOriginal.Error = toolExecutionText(copyOriginal.Error)
	copyOriginal.PartialOutput = toolExecutionText(copyOriginal.PartialOutput)
	snapshot, hash, err := ingestionSnapshotJSON(ResultIngestionSnapshot{Execution: e, Original: &copyOriginal, Projection: projection})
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Reserve SQLite's writer before reading (avoids read-to-write snapshot
	// upgrade failures under concurrent observers); PostgreSQL locks this job.
	if _, err = tx.ExecContext(ctx, `UPDATE result_ingestion_jobs SET updated_at_ms=updated_at_ms WHERE execution_id=?`, e.ID); err != nil {
		return err
	}
	var existingBody string
	existingErr := tx.QueryRowContext(ctx, `SELECT snapshot_json FROM result_ingestion_snapshots WHERE execution_id=?`, e.ID).Scan(&existingBody)
	if existingErr == nil {
		var existing ResultIngestionSnapshot
		if json.Unmarshal([]byte(existingBody), &existing) != nil || !sameIngestionBinding(existing.Execution, e) {
			return evidence.ErrDenied
		}
		// A duplicate observer event cannot regress a completed/failed job,
		// update authority, or undo conservative parsing completeness metadata.
		return nil
	}
	if !errors.Is(existingErr, sql.ErrNoRows) {
		return existingErr
	}
	var oldJobCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM result_ingestion_jobs WHERE execution_id=?`, e.ID).Scan(&oldJobCount); err != nil {
		return err
	}
	if oldJobCount != 0 {
		// Pre-migration jobs never had a historical permission snapshot.
		snapshot, hash, err = ingestionSnapshotJSON(ResultIngestionSnapshot{Execution: e, Original: &copyOriginal})
		if err != nil {
			return err
		}
	}
	// The guarded upsert mirrors RecordExecution, but is in this transaction so
	// a terminal metadata write cannot race ahead of its durable queue marker.
	res, err := tx.ExecContext(ctx, `INSERT INTO result_execution_metadata (`+resultExecutionColumns+`)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(execution_id) DO UPDATE SET
 parser_tool=excluded.parser_tool,status=excluded.status,completion=excluded.completion,timed_out=excluded.timed_out,
 capped=excluded.capped,output_bytes=excluded.output_bytes,finished_at_ms=excluded.finished_at_ms
 WHERE result_execution_metadata.project_id=excluded.project_id AND result_execution_metadata.conversation_id=excluded.conversation_id
 AND result_execution_metadata.owner=excluded.owner AND result_execution_metadata.scope_id=excluded.scope_id
 AND result_execution_metadata.assessment_id=excluded.assessment_id AND result_execution_metadata.tool=excluded.tool
 AND result_execution_metadata.started_at_ms=excluded.started_at_ms
 AND (result_execution_metadata.parser_tool='' OR result_execution_metadata.parser_tool=excluded.parser_tool)`,
		e.ID, e.ProjectID, e.ConversationID, e.Owner, e.ScopeID, e.AssessmentID, e.Tool, e.ParserTool, e.Status, e.Completion, resultBool(e.TimedOut), resultBool(e.Capped), e.OutputBytes, resultMillis(e.StartedAt), resultMillis(e.FinishedAt))
	if err = ingestionAffected(res, err, evidence.ErrDenied); err != nil {
		return err
	}
	// Subsequent monitor persistence/reduction may update the display copy. The
	// queue's frozen snapshot is insert-only and never follows that mutable copy.
	res, err = tx.ExecContext(ctx, `INSERT INTO tool_executions
 (id,tool_name,arguments,status,result,error,start_time,end_time,duration_ms,partial_output,partial_output_bytes,partial_output_truncated,partial_output_updated_at,owner_user_id,conversation_id,created_at)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
 arguments=excluded.arguments,status=excluded.status,result=excluded.result,error=excluded.error,end_time=excluded.end_time,duration_ms=excluded.duration_ms,
 partial_output=excluded.partial_output,partial_output_bytes=excluded.partial_output_bytes,partial_output_truncated=excluded.partial_output_truncated,partial_output_updated_at=excluded.partial_output_updated_at
 WHERE tool_executions.owner_user_id=excluded.owner_user_id AND tool_executions.conversation_id=excluded.conversation_id AND tool_executions.tool_name=excluded.tool_name`,
		original.ID, original.ToolName, string(args), original.Status, resultJSON, sqlNullString(original.Error), original.StartTime, *original.EndTime,
		original.Duration.Milliseconds(), sqlNullString(original.PartialOutput), original.PartialOutputBytes, resultBool(original.PartialOutputTruncated), original.PartialOutputUpdatedAt, original.OwnerUserID, original.ConversationID, time.Now())
	if err = ingestionAffected(res, err, evidence.ErrDenied); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO result_ingestion_jobs(execution_id,project_id,conversation_id,owner,assessment_id,scope_id,state,reason,updated_at_ms)
 VALUES(?,?,?,?,?,?,'pending','',?) ON CONFLICT(execution_id) DO NOTHING`, e.ID, e.ProjectID, e.ConversationID, e.Owner, e.AssessmentID, e.ScopeID, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	j, err := scanIngestionJob(tx.QueryRowContext(ctx, `SELECT `+ingestionJobColumns+` FROM result_ingestion_jobs WHERE execution_id=?`, e.ID))
	if err != nil {
		return err
	}
	if !jobMatchesExecution(j, e) {
		return evidence.ErrDenied
	}
	// Never silently requeue a failed row or overwrite an older authority bound.
	_, err = tx.ExecContext(ctx, `INSERT INTO result_ingestion_snapshots(execution_id,snapshot_json,sha256) VALUES(?,?,?) ON CONFLICT(execution_id) DO NOTHING`, e.ID, snapshot, hash)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func jobMatchesExecution(j ResultIngestionJob, e evidence.Execution) bool {
	return j.ExecutionID == e.ID && j.Access == e.Access && j.AssessmentID == e.AssessmentID && j.ScopeID == e.ScopeID
}

// LoadResultIngestionSnapshot loads at most one original, after claiming it. Old
// rows use tool_executions plus result_execution_metadata, never the conversation's
// current project/run/scope. Invalid/missing original JSON is an explicit failure.
// The first legacy load freezes a snapshot without inventing historical RBAC.
func (db *DB) LoadResultIngestionSnapshot(ctx context.Context, j ResultIngestionJob) (ResultIngestionSnapshot, error) {
	var s ResultIngestionSnapshot
	if err := db.CheckResultIngestionLease(ctx, j); err != nil {
		return s, err
	}
	ctx = evidence.WithAccess(ctx, j.Access)
	e, err := db.ResultExecution(ctx, j.ExecutionID)
	if err != nil {
		return s, err
	}
	if !jobMatchesExecution(j, e) {
		return s, evidence.ErrDenied
	}
	var body, hash string
	err = db.QueryRowContext(ctx, `SELECT snapshot_json,sha256 FROM result_ingestion_snapshots WHERE execution_id=?`, j.ExecutionID).Scan(&body, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		original, loadErr := db.loadIngestionOriginal(ctx, j.ExecutionID)
		if loadErr != nil {
			return s, loadErr
		}
		if err = validateIngestionOriginal(e, original); err != nil {
			return s, err
		}
		s = ResultIngestionSnapshot{Execution: e, Original: original}
		body, hash, err = ingestionSnapshotJSON(s)
		if err != nil {
			return s, err
		}
		args := append([]interface{}{j.ExecutionID, body, hash}, ingestionLeaseArgs(j)...)
		res, saveErr := db.ExecContext(ctx, `INSERT INTO result_ingestion_snapshots(execution_id,snapshot_json,sha256)
 SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM result_ingestion_jobs WHERE `+ingestionLeaseWhere+`) ON CONFLICT(execution_id) DO NOTHING`, args...)
		if err = ingestionAffected(res, saveErr, ErrResultIngestionLeaseLost); err != nil {
			return s, err
		}
	} else if err != nil {
		return s, err
	} else {
		sum := sha256.Sum256([]byte(body))
		if hex.EncodeToString(sum[:]) != hash {
			return s, evidence.ErrChanged
		}
		if err = json.Unmarshal([]byte(body), &s); err != nil {
			return s, fmt.Errorf("invalid ingestion snapshot JSON: %w", errors.Join(evidence.ErrDenied, err))
		}
	}
	if !sameIngestionBinding(e, s.Execution) || e.Status != s.Execution.Status || resultMillis(e.FinishedAt) != resultMillis(s.Execution.FinishedAt) ||
		s.Projection.Owner != "" && s.Projection.Owner != e.Owner {
		return s, evidence.ErrDenied
	}
	if err = validateIngestionOriginal(s.Execution, s.Original); err != nil {
		return s, err
	}
	// The monitor copy may have been reduced, but identity must still agree. A
	// retained immutable snapshot can survive monitor retention (a deleted row).
	var owner, conversation, tool string
	err = db.QueryRowContext(ctx, `SELECT COALESCE(owner_user_id,''),COALESCE(conversation_id,''),tool_name FROM tool_executions WHERE id=?`, e.ID).Scan(&owner, &conversation, &tool)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return s, err
	}
	if err == nil && (owner != e.Owner || conversation != e.ConversationID || tool != e.Tool) {
		return s, evidence.ErrDenied
	}
	// Preserve any conservative completeness downgrade already recorded by parsing.
	s.Execution = e
	return s, db.CheckResultIngestionLease(ctx, j)
}

func (db *DB) loadIngestionOriginal(ctx context.Context, id string) (*mcp.ToolExecution, error) {
	var o mcp.ToolExecution
	var arguments string
	var result sql.NullString
	var end sql.NullTime
	var truncated int
	err := db.QueryRowContext(ctx, `SELECT id,tool_name,arguments,status,result,start_time,end_time,
 COALESCE(partial_output_truncated,0),COALESCE(owner_user_id,''),COALESCE(conversation_id,'') FROM tool_executions WHERE id=?`, id).
		Scan(&o.ID, &o.ToolName, &arguments, &o.Status, &result, &o.StartTime, &end, &truncated, &o.OwnerUserID, &o.ConversationID)
	if err != nil {
		return nil, fmt.Errorf("saved tool result unavailable: %w", err)
	}
	if err = json.Unmarshal([]byte(arguments), &o.Arguments); err != nil {
		return nil, fmt.Errorf("saved tool arguments invalid: %w", errors.Join(evidence.ErrDenied, err))
	}
	if result.Valid && result.String != "" {
		if err = json.Unmarshal([]byte(result.String), &o.Result); err != nil {
			return nil, fmt.Errorf("saved tool result invalid: %w", errors.Join(evidence.ErrDenied, err))
		}
	}
	if end.Valid {
		o.EndTime = &end.Time
	}
	o.PartialOutputTruncated = truncated != 0
	return &o, nil
}
