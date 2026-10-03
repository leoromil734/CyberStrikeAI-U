package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
)

// ResultArtifactsSchema deliberately contains only execution metadata, artifact
// metadata, structured inventory and provenance. There is no output/body column.
// Statements are executed through the existing SQLite/PostgreSQL SQL adapter.
const ResultArtifactsSchema = `
CREATE TABLE IF NOT EXISTS result_execution_metadata (
 execution_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
 owner TEXT NOT NULL, scope_id TEXT NOT NULL, assessment_id TEXT NOT NULL,
 tool TEXT NOT NULL, parser_tool TEXT NOT NULL, status TEXT NOT NULL, completion TEXT NOT NULL,
 timed_out INTEGER NOT NULL, capped INTEGER NOT NULL, output_bytes BIGINT NOT NULL,
 started_at_ms BIGINT NOT NULL, finished_at_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS result_artifacts (
 id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, project_id TEXT NOT NULL,
 conversation_id TEXT NOT NULL, owner TEXT NOT NULL, kind TEXT NOT NULL,
 path TEXT NOT NULL, size BIGINT NOT NULL, sha256 TEXT NOT NULL, format TEXT NOT NULL,
 completion TEXT NOT NULL, parse_state TEXT NOT NULL, stats_json TEXT NOT NULL,
 created_at_ms BIGINT NOT NULL, artifact_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_result_artifacts_execution ON result_artifacts(execution_id);
CREATE TABLE IF NOT EXISTS recon_sources (
 id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
 project_id TEXT NOT NULL, conversation_id TEXT NOT NULL, owner TEXT NOT NULL,
 scope_id TEXT NOT NULL, assessment_id TEXT NOT NULL, sha256 TEXT NOT NULL,
 tool TEXT NOT NULL, format TEXT NOT NULL, parser_version TEXT NOT NULL,
 completion TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL,
 stats_json TEXT NOT NULL, inserted_json TEXT NOT NULL,
 observed_at_ms BIGINT NOT NULL, expires_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recon_sources_partition ON recon_sources(project_id,scope_id,assessment_id,owner,conversation_id);
CREATE TABLE IF NOT EXISTS recon_inventory (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
 owner TEXT NOT NULL, scope_id TEXT NOT NULL, assessment_id TEXT NOT NULL,
 kind TEXT NOT NULL, host TEXT NOT NULL, raw_host TEXT NOT NULL, ip TEXT NOT NULL,
 port INTEGER NOT NULL, raw_port TEXT NOT NULL, protocol TEXT NOT NULL,
 raw_url TEXT NOT NULL, raw_path TEXT NOT NULL, method TEXT NOT NULL, service_name TEXT NOT NULL,
 template_id TEXT NOT NULL, severity TEXT NOT NULL, scope_state TEXT NOT NULL,
 candidate_only INTEGER NOT NULL, first_source_id TEXT NOT NULL,
 artifact_id TEXT NOT NULL, execution_id TEXT NOT NULL,
 source_offset BIGINT NOT NULL, source_length BIGINT NOT NULL, source_line BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recon_inventory_partition ON recon_inventory(project_id,scope_id,assessment_id,owner,conversation_id,kind);
CREATE TABLE IF NOT EXISTS recon_record_sources (
 record_id TEXT NOT NULL, source_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
 execution_id TEXT NOT NULL, source_offset BIGINT NOT NULL, source_length BIGINT NOT NULL,
 source_line BIGINT NOT NULL, PRIMARY KEY(record_id,source_id)
);
CREATE INDEX IF NOT EXISTS idx_recon_record_sources_source ON recon_record_sources(source_id);
`

// initResultArtifactsTables is the only initTables seam. This module does not
// modify the main database initialization; the caller must wire this explicitly.
func (db *DB) initResultArtifactsTables() error {
	for _, statement := range splitSQLStatements(ResultArtifactsSchema) {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize result artifact tables: %w", err)
		}
	}
	return nil
}

// InitResultArtifactsTables is useful for explicit initialization in integration
// tests and external bootstrappers. Normal application startup should call the
// package-private initializer from initTables.
func (db *DB) InitResultArtifactsTables() error { return db.initResultArtifactsTables() }

func resultBool(value bool) int {
	if value {
		return 1
	}
	return 0
}
func resultMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixMilli()
}
func resultTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func (db *DB) RecordExecution(ctx context.Context, e evidence.Execution) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	if e.TimedOut {
		e.Completion = evidence.Partial
	}
	result, err := db.ExecContext(ctx, `INSERT INTO result_execution_metadata
 (execution_id,project_id,conversation_id,owner,scope_id,assessment_id,tool,parser_tool,status,completion,timed_out,capped,output_bytes,started_at_ms,finished_at_ms)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(execution_id) DO UPDATE SET
 parser_tool=excluded.parser_tool,status=excluded.status, completion=excluded.completion,timed_out=excluded.timed_out,
 capped=excluded.capped,output_bytes=excluded.output_bytes,finished_at_ms=excluded.finished_at_ms
 WHERE result_execution_metadata.project_id=excluded.project_id
 AND result_execution_metadata.conversation_id=excluded.conversation_id
 AND result_execution_metadata.owner=excluded.owner AND result_execution_metadata.scope_id=excluded.scope_id
 AND result_execution_metadata.assessment_id=excluded.assessment_id AND result_execution_metadata.tool=excluded.tool
 AND (result_execution_metadata.parser_tool='' OR result_execution_metadata.parser_tool=excluded.parser_tool)`,
		e.ID, e.ProjectID, e.ConversationID, e.Owner, e.ScopeID, e.AssessmentID, e.Tool, e.ParserTool, e.Status, e.Completion, resultBool(e.TimedOut), resultBool(e.Capped), e.OutputBytes, resultMillis(e.StartedAt), resultMillis(e.FinishedAt))
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return evidence.ErrDenied
	}
	if e.Completion != evidence.Complete {
		if _, err = db.ExecContext(ctx, `UPDATE result_artifacts SET completion=? WHERE execution_id=? AND project_id=? AND conversation_id=? AND owner=? AND completion='complete'`, e.Completion, e.ID, e.ProjectID, e.ConversationID, e.Owner); err != nil {
			return err
		}
	}
	return nil
}

const resultExecutionColumns = `execution_id,project_id,conversation_id,owner,scope_id,assessment_id,tool,parser_tool,status,completion,timed_out,capped,output_bytes,started_at_ms,finished_at_ms`

type resultScanner interface{ Scan(...interface{}) error }

func scanResultExecution(row resultScanner) (evidence.Execution, error) {
	var e evidence.Execution
	var timeout, capped int
	var start, end int64
	err := row.Scan(&e.ID, &e.ProjectID, &e.ConversationID, &e.Owner, &e.ScopeID, &e.AssessmentID, &e.Tool, &e.ParserTool, &e.Status, &e.Completion, &timeout, &capped, &e.OutputBytes, &start, &end)
	e.TimedOut = timeout != 0
	e.Capped = capped != 0
	e.StartedAt = resultTime(start)
	e.FinishedAt = resultTime(end)
	return e, err
}
func (db *DB) ResultExecution(ctx context.Context, id string) (evidence.Execution, error) {
	access, err := evidence.AccessFromContext(ctx)
	if err != nil {
		return evidence.Execution{}, err
	}
	e, err := scanResultExecution(db.QueryRowContext(ctx, `SELECT `+resultExecutionColumns+` FROM result_execution_metadata WHERE execution_id=? AND project_id=? AND conversation_id=? AND owner=?`, id, access.ProjectID, access.ConversationID, access.Owner))
	if errors.Is(err, sql.ErrNoRows) {
		return evidence.Execution{}, evidence.ErrDenied
	}
	return e, err
}

const resultArtifactColumns = `id,execution_id,project_id,conversation_id,owner,kind,path,size,sha256,format,completion,parse_state,stats_json,created_at_ms`

func scanResultArtifact(row resultScanner) (evidence.Artifact, error) {
	var a evidence.Artifact
	var stats string
	var at int64
	err := row.Scan(&a.ID, &a.ExecutionID, &a.ProjectID, &a.ConversationID, &a.Owner, &a.Kind, &a.Path, &a.Size, &a.SHA256, &a.Format, &a.Completion, &a.ParseState, &stats, &at)
	if err != nil {
		return a, err
	}
	if err = json.Unmarshal([]byte(stats), &a.Stats); err != nil {
		return evidence.Artifact{}, err
	}
	a.CreatedAt = resultTime(at)
	return a, nil
}

func (db *DB) RegisterArtifact(ctx context.Context, verified evidence.VerifiedArtifact) (evidence.Artifact, error) {
	a, err := verified.Metadata()
	if err != nil {
		return evidence.Artifact{}, err
	}
	e, err := db.ResultExecution(ctx, a.ExecutionID)
	if err != nil {
		return evidence.Artifact{}, err
	}
	if e.Access != a.Access || !evidence.ValidCompletion(a.Completion) || a.Size < 0 || len(a.SHA256) != 64 || len(a.Path) > 8192 {
		return evidence.Artifact{}, evidence.ErrDenied
	}
	if e.Completion != evidence.Complete && a.Completion == evidence.Complete {
		return evidence.Artifact{}, evidence.ErrDenied
	}
	stats, _ := json.Marshal(a.Stats)
	keyData, _ := json.Marshal([]string{a.ExecutionID, a.Path, a.SHA256, a.Kind, a.Format})
	keyHash := sha256.Sum256(keyData)
	key := hex.EncodeToString(keyHash[:])
	_, err = db.ExecContext(ctx, `INSERT INTO result_artifacts (`+resultArtifactColumns+`,artifact_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
 ON CONFLICT(artifact_key) DO NOTHING`, a.ID, a.ExecutionID, a.ProjectID, a.ConversationID, a.Owner, a.Kind, a.Path, a.Size, a.SHA256, a.Format, a.Completion, a.ParseState, string(stats), resultMillis(a.CreatedAt), key)
	if err != nil {
		return evidence.Artifact{}, err
	}
	if a.Completion != evidence.Complete {
		if _, err = db.ExecContext(ctx, `UPDATE result_artifacts SET completion=? WHERE artifact_key=? AND completion='complete'`, a.Completion, key); err != nil {
			return evidence.Artifact{}, err
		}
	}
	return scanResultArtifact(db.QueryRowContext(ctx, `SELECT `+resultArtifactColumns+` FROM result_artifacts WHERE artifact_key=? AND project_id=? AND conversation_id=? AND owner=?`, key, a.ProjectID, a.ConversationID, a.Owner))
}

func (db *DB) ResultArtifact(ctx context.Context, id string) (evidence.Artifact, error) {
	access, err := evidence.AccessFromContext(ctx)
	if err != nil {
		return evidence.Artifact{}, err
	}
	a, err := scanResultArtifact(db.QueryRowContext(ctx, `SELECT `+resultArtifactColumns+` FROM result_artifacts WHERE id=? AND project_id=? AND conversation_id=? AND owner=?`, id, access.ProjectID, access.ConversationID, access.Owner))
	if errors.Is(err, sql.ErrNoRows) {
		return evidence.Artifact{}, evidence.ErrDenied
	}
	if err != nil {
		return evidence.Artifact{}, err
	}
	e, err := db.ResultExecution(ctx, a.ExecutionID)
	if err != nil || e.Access != a.Access {
		return evidence.Artifact{}, evidence.ErrDenied
	}
	return a, nil
}

func resultPage(limit, offset int) (int, int, error) {
	if offset < 0 {
		return 0, 0, evidence.ErrLimit
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return limit, offset, nil
}
func (db *DB) ResultArtifacts(ctx context.Context, executionID string, limit, offset int) ([]evidence.Artifact, error) {
	e, err := db.ResultExecution(ctx, executionID)
	if err != nil {
		return nil, err
	}
	limit, offset, err = resultPage(limit, offset)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT `+resultArtifactColumns+` FROM result_artifacts WHERE execution_id=? AND project_id=? AND conversation_id=? AND owner=? ORDER BY created_at_ms,id LIMIT ? OFFSET ?`, executionID, e.ProjectID, e.ConversationID, e.Owner, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []evidence.Artifact{}
	for rows.Next() {
		a, err := scanResultArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

const reconSourceColumns = `id,execution_id,artifact_id,project_id,conversation_id,owner,scope_id,assessment_id,sha256,tool,format,parser_version,completion,state,reason,stats_json,inserted_json,observed_at_ms,expires_at_ms`

func scanReconSource(row resultScanner) (recon.Source, error) {
	var s recon.Source
	var stats, inserted string
	var at, expires int64
	err := row.Scan(&s.ID, &s.ExecutionID, &s.ArtifactID, &s.ProjectID, &s.ConversationID, &s.Owner, &s.ScopeID, &s.AssessmentID, &s.SHA256, &s.Tool, &s.Format, &s.ParserVersion, &s.Completion, &s.State, &s.Reason, &stats, &inserted, &at, &expires)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal([]byte(stats), &s.Stats); err != nil {
		return s, err
	}
	if err = json.Unmarshal([]byte(inserted), &s.Inserted); err != nil {
		return s, err
	}
	s.ObservedAt = resultTime(at)
	s.ExpiresAt = resultTime(expires)
	return s, nil
}

func reconStateValid(state string) bool {
	switch state {
	case evidence.Parsed, evidence.Partial, evidence.Unsupported, evidence.Invalid, evidence.Error, recon.MissingOriginal:
		return true
	}
	return false
}
func (db *DB) validateReconSource(ctx context.Context, s recon.Source, records []recon.Record) (evidence.Execution, evidence.Artifact, error) {
	e, err := db.ResultExecution(ctx, s.ExecutionID)
	if err != nil {
		return e, evidence.Artifact{}, err
	}
	if s.Access != e.Access || s.ScopeID != e.ScopeID || s.AssessmentID != e.AssessmentID || s.Tool != recon.CanonicalTool(e.OutputTool()) {
		return e, evidence.Artifact{}, evidence.ErrDenied
	}
	if s.ParserVersion == "" || len(s.ParserVersion) > 64 || len(s.Tool) > 128 || len(s.Format) > 32 || len(s.Reason) > 64 || !reconStateValid(s.State) || !evidence.ValidCompletion(s.Completion) || len(records) > 100000 {
		return e, evidence.Artifact{}, errors.New("invalid recon source metadata")
	}
	if s.State == evidence.Unsupported || s.State == evidence.Invalid || s.State == evidence.Error || s.State == recon.MissingOriginal {
		if len(records) > 0 {
			return e, evidence.Artifact{}, errors.New("non-parsed source cannot import records")
		}
	}
	if s.ArtifactID == "" {
		if len(records) > 0 || s.State != recon.MissingOriginal || s.SHA256 != "" {
			return e, evidence.Artifact{}, evidence.ErrDenied
		}
		return e, evidence.Artifact{}, nil
	}
	a, err := db.ResultArtifact(ctx, s.ArtifactID)
	if err != nil {
		return e, a, err
	}
	if a.ExecutionID != e.ID || a.SHA256 != s.SHA256 || a.Format != s.Format || a.Kind == "input" || a.Completion != evidence.Complete && s.Completion == evidence.Complete {
		return e, a, evidence.ErrDenied
	}
	for _, r := range records {
		if err := r.Validate(); err != nil {
			return e, a, err
		}
		if s.Tool == "nuclei" && (r.Kind != recon.Candidate || !r.CandidateOnly) {
			return e, a, evidence.ErrDenied
		}
		if r.ArtifactID != a.ID || r.ExecutionID != e.ID || r.Location.Offset < 0 || r.Location.Length < 0 || r.Location.Offset > a.Size || r.Location.Length > a.Size-r.Location.Offset {
			return e, a, evidence.ErrDenied
		}
		if (e.ProjectID == "" || e.ScopeID == "" || e.AssessmentID == "") && !r.CandidateOnly {
			return e, a, evidence.ErrDenied
		}
	}
	return e, a, nil
}

func inventoryKey(e evidence.Execution, r recon.Record) string {
	raw, _ := json.Marshal([]string{e.ProjectID, e.ScopeID, e.AssessmentID, e.Owner, e.ConversationID, r.Identity()})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// ImportReconSource is a single transaction. RowsAffected is the actual inventory
// delta, rather than a tool's advertised count, a preview count or a row count
// before deduplication. Provenance is recorded even when the inventory delta is 0.
func (db *DB) ImportReconSource(ctx context.Context, s recon.Source, records []recon.Record) (recon.ImportResult, error) {
	e, a, err := db.validateReconSource(ctx, s, records)
	if err != nil {
		return recon.ImportResult{}, err
	}
	s.ID = s.Key()
	s.Inserted = recon.Counts{}
	stats, _ := json.Marshal(s.Stats)
	inserted, _ := json.Marshal(s.Inserted)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return recon.ImportResult{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO recon_sources (`+reconSourceColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		s.ID, s.ExecutionID, s.ArtifactID, s.ProjectID, s.ConversationID, s.Owner, s.ScopeID, s.AssessmentID, s.SHA256, s.Tool, s.Format, s.ParserVersion, s.Completion, s.State, s.Reason, string(stats), string(inserted), resultMillis(s.ObservedAt), resultMillis(s.ExpiresAt))
	if err != nil {
		return recon.ImportResult{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return recon.ImportResult{}, err
	}
	if n == 0 {
		stored, err := scanReconSource(tx.QueryRowContext(ctx, `SELECT `+reconSourceColumns+` FROM recon_sources WHERE id=?`, s.ID))
		if err != nil {
			return recon.ImportResult{}, err
		}
		if (s.Completion != evidence.Complete && stored.Completion == evidence.Complete) || (s.State == evidence.Error && stored.State != evidence.Error) {
			stored.Completion = s.Completion
			stored.State = s.State
			stored.Reason = s.Reason
			if _, err = tx.ExecContext(ctx, `UPDATE recon_sources SET completion=?,state=?,reason=? WHERE id=?`, stored.Completion, stored.State, stored.Reason, stored.ID); err != nil {
				return recon.ImportResult{}, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE result_artifacts SET parse_state=? WHERE id=?`, stored.State, a.ID); err != nil {
				return recon.ImportResult{}, err
			}
		}
		if err = tx.Commit(); err != nil {
			return recon.ImportResult{}, err
		}
		return recon.ImportResult{Source: stored, Duplicate: true}, nil
	}
	output := []recon.Record{}
	seen := map[string]bool{}
	for _, r := range records {
		id := inventoryKey(e, r)
		if seen[id] {
			continue
		}
		seen[id] = true
		r.ID = id
		r.SourceID = s.ID
		res, err = tx.ExecContext(ctx, `INSERT INTO recon_inventory
  (id,project_id,conversation_id,owner,scope_id,assessment_id,kind,host,raw_host,ip,port,raw_port,protocol,raw_url,raw_path,method,service_name,template_id,severity,scope_state,candidate_only,first_source_id,artifact_id,execution_id,source_offset,source_length,source_line)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
			id, e.ProjectID, e.ConversationID, e.Owner, e.ScopeID, e.AssessmentID, r.Kind, r.Host, r.RawHost, r.IP, r.Port, r.RawPort, r.Protocol, r.RawURL, r.RawPath, r.Method, r.ServiceName, r.TemplateID, r.Severity, r.ScopeState, resultBool(r.CandidateOnly), s.ID, a.ID, e.ID, r.Location.Offset, r.Location.Length, r.Location.Line)
		if err != nil {
			return recon.ImportResult{}, err
		}
		n, err = res.RowsAffected()
		if err != nil {
			return recon.ImportResult{}, err
		}
		if n > 0 {
			s.Inserted.Add(r.Kind)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO recon_record_sources(record_id,source_id,artifact_id,execution_id,source_offset,source_length,source_line)
  VALUES (?,?,?,?,?,?,?) ON CONFLICT(record_id,source_id) DO NOTHING`, id, s.ID, a.ID, e.ID, r.Location.Offset, r.Location.Length, r.Location.Line)
		if err != nil {
			return recon.ImportResult{}, err
		}
		output = append(output, r)
	}
	inserted, _ = json.Marshal(s.Inserted)
	if _, err = tx.ExecContext(ctx, `UPDATE recon_sources SET inserted_json=? WHERE id=?`, string(inserted), s.ID); err != nil {
		return recon.ImportResult{}, err
	}
	if a.ID != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE result_artifacts SET parse_state=?,stats_json=? WHERE id=? AND execution_id=? AND project_id=? AND conversation_id=? AND owner=?`, s.State, string(stats), a.ID, e.ID, e.ProjectID, e.ConversationID, e.Owner); err != nil {
			return recon.ImportResult{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return recon.ImportResult{}, err
	}
	return recon.ImportResult{Source: s, Inserted: s.Inserted, Records: output}, nil
}

const reconRecordColumns = `id,kind,host,raw_host,ip,port,raw_port,protocol,raw_url,raw_path,method,service_name,template_id,severity,scope_state,candidate_only,first_source_id,artifact_id,execution_id,source_offset,source_length,source_line`

func scanReconRecord(row resultScanner) (recon.Record, error) {
	var r recon.Record
	var candidate int
	err := row.Scan(&r.ID, &r.Kind, &r.Host, &r.RawHost, &r.IP, &r.Port, &r.RawPort, &r.Protocol, &r.RawURL, &r.RawPath, &r.Method, &r.ServiceName, &r.TemplateID, &r.Severity, &r.ScopeState, &candidate, &r.SourceID, &r.ArtifactID, &r.ExecutionID, &r.Location.Offset, &r.Location.Length, &r.Location.Line)
	r.CandidateOnly = candidate != 0
	return r, err
}

func reconPartitionArgs(e evidence.Execution) []interface{} {
	return []interface{}{e.ProjectID, e.ScopeID, e.AssessmentID, e.Owner, e.ConversationID}
}

const reconPartition = `project_id=? AND scope_id=? AND assessment_id=? AND owner=? AND conversation_id=?`

func (db *DB) ReconInventory(ctx context.Context, executionID, kind string, limit, offset int) ([]recon.Record, error) {
	e, err := db.ResultExecution(ctx, executionID)
	if err != nil {
		return nil, err
	}
	limit, offset, err = resultPage(limit, offset)
	if err != nil {
		return nil, err
	}
	query := `SELECT ` + reconRecordColumns + ` FROM recon_inventory WHERE ` + reconPartition
	args := reconPartitionArgs(e)
	if kind != "" {
		switch kind {
		case recon.Host, recon.Service, recon.Endpoint, recon.JS, recon.Candidate:
		default:
			return nil, errors.New("invalid inventory kind")
		}
		query += ` AND kind=?`
		args = append(args, kind)
	}
	query += ` ORDER BY kind,id LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []recon.Record{}
	for rows.Next() {
		r, err := scanReconRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) ReconInventoryCounts(ctx context.Context, executionID string) (recon.Counts, error) {
	e, err := db.ResultExecution(ctx, executionID)
	if err != nil {
		return recon.Counts{}, err
	}
	rows, err := db.QueryContext(ctx, `SELECT kind,COUNT(*) FROM recon_inventory WHERE `+reconPartition+` GROUP BY kind`, reconPartitionArgs(e)...)
	if err != nil {
		return recon.Counts{}, err
	}
	defer rows.Close()
	var c recon.Counts
	for rows.Next() {
		var kind string
		var count int64
		if err = rows.Scan(&kind, &count); err != nil {
			return recon.Counts{}, err
		}
		switch kind {
		case recon.Host:
			c.Hosts = count
		case recon.Service:
			c.Services = count
		case recon.Endpoint:
			c.Endpoints = count
		case recon.JS:
			c.JS = count
		case recon.Candidate:
			c.Candidates = count
		}
	}
	return c, rows.Err()
}

// ReconSources returns sources in the execution's exact partition, including
// other executions of that same assessment, and computes expiration at read time.
func (db *DB) ReconSources(ctx context.Context, executionID string, limit, offset int, now time.Time) ([]recon.Source, error) {
	e, err := db.ResultExecution(ctx, executionID)
	if err != nil {
		return nil, err
	}
	limit, offset, err = resultPage(limit, offset)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	args := append(reconPartitionArgs(e), limit, offset)
	rows, err := db.QueryContext(ctx, `SELECT `+reconSourceColumns+` FROM recon_sources WHERE `+reconPartition+` ORDER BY observed_at_ms,id LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []recon.Source{}
	for rows.Next() {
		s, err := scanReconSource(rows)
		if err != nil {
			return nil, err
		}
		s.Expired = !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ReconSourceRecords pages provenance for a specific source, rather than only
// the inventory's first location. Each location can be passed to ReadRegion.
func (db *DB) ReconSourceRecords(ctx context.Context, sourceID string, limit, offset int) ([]recon.Record, error) {
	access, err := evidence.AccessFromContext(ctx)
	if err != nil {
		return nil, err
	}
	s, err := scanReconSource(db.QueryRowContext(ctx, `SELECT `+reconSourceColumns+` FROM recon_sources WHERE id=? AND project_id=? AND conversation_id=? AND owner=?`, sourceID, access.ProjectID, access.ConversationID, access.Owner))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, evidence.ErrDenied
	}
	if err != nil {
		return nil, err
	}
	if _, err = db.ResultExecution(ctx, s.ExecutionID); err != nil {
		return nil, err
	}
	limit, offset, err = resultPage(limit, offset)
	if err != nil {
		return nil, err
	}
	// A prefix on all columns prevents ambiguity without adding dialect-specific SQL.
	columns := strings.Split(reconRecordColumns, ",")
	for i, col := range columns {
		columns[i] = "r." + col
	}
	columns[len(columns)-6] = "p.source_id"
	columns[len(columns)-5] = "p.artifact_id"
	columns[len(columns)-4] = "p.execution_id"
	columns[len(columns)-3] = "p.source_offset"
	columns[len(columns)-2] = "p.source_length"
	columns[len(columns)-1] = "p.source_line"
	rows, err := db.QueryContext(ctx, `SELECT `+strings.Join(columns, ",")+` FROM recon_inventory r JOIN recon_record_sources p ON p.record_id=r.id WHERE p.source_id=? AND r.project_id=? AND r.scope_id=? AND r.assessment_id=? AND r.owner=? AND r.conversation_id=? ORDER BY r.kind,r.id LIMIT ? OFFSET ?`, s.ID, s.ProjectID, s.ScopeID, s.AssessmentID, s.Owner, s.ConversationID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []recon.Record{}
	for rows.Next() {
		r, err := scanReconRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var _ evidence.Store = (*DB)(nil)
var _ recon.Store = (*DB)(nil)
