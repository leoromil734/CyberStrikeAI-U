package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/evidence"
)

// CoverageOriginalBinding resolves trusted current ownership and scope. A change
// of project, owner or authorized scope cannot import a previous run's proofs.
// Missing ownership fails closed; it is never guessed from an arbitrary tool row.
func (db *DB) CoverageOriginalBinding(projectID, conversationID, assessmentID string) (coverage.OriginalBinding, error) {
	b := coverage.OriginalBinding{Access: evidence.Access{ProjectID: projectID, ConversationID: conversationID}, AssessmentID: assessmentID}
	var boundProject, scope string
	err := db.QueryRow(`SELECT COALESCE(c.owner_user_id,''),COALESCE(c.project_id,''),COALESCE(p.scope_json,'') FROM conversations c JOIN projects p ON p.id=c.project_id WHERE c.id=?`, conversationID).Scan(&b.Owner, &boundProject, &scope)
	if err != nil {
		return b, err
	}
	if b.Owner == "" || boundProject != projectID || assessmentID == "" {
		return b, evidence.ErrDenied
	}
	sum := sha256.Sum256([]byte(scope))
	b.ScopeID = "scope-" + hex.EncodeToString(sum[:16])
	return b, nil
}

// AssessmentHTTPExecutions includes generic executors only as candidates. A
// completed row alone never becomes evidence; the caller must verify full input
// and output originals with coverage.VerifyHTTPOriginal and a trusted registry.
func (db *DB) AssessmentHTTPExecutions(ctx context.Context, b coverage.OriginalBinding) ([]evidence.Execution, error) {
	if err := b.Access.Authorize(ctx); err != nil {
		return nil, err
	}
	if b.ProjectID == "" || b.ScopeID == "" || b.AssessmentID == "" {
		return nil, evidence.ErrDenied
	}
	rows, err := db.QueryContext(ctx, `SELECT `+resultExecutionColumns+` FROM result_execution_metadata WHERE project_id=? AND conversation_id=? AND owner=? AND assessment_id=? AND scope_id=? AND tool IN ('exec','execute','curl','http-framework-test') AND status='completed' AND completion='complete' AND timed_out=0 AND capped=0 ORDER BY execution_id LIMIT 2001`, b.ProjectID, b.ConversationID, b.Owner, b.AssessmentID, b.ScopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []evidence.Execution{}
	for rows.Next() {
		e, err := scanResultExecution(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if len(out) > 2000 {
		return nil, fmt.Errorf("HTTP original comparison limit exceeded")
	}
	return out, rows.Err()
}

// CoverageSourceAliases binds legacy recon source IDs to the verified captured
// output, without trusting their parse state or allowing another partition.
func (db *DB) CoverageSourceAliases(ctx context.Context, e evidence.Execution, artifactID string) ([]string, error) {
	if err := e.Access.Authorize(ctx); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT s.id FROM recon_sources s JOIN result_artifacts a ON a.id=s.artifact_id AND a.execution_id=s.execution_id AND a.project_id=s.project_id AND a.conversation_id=s.conversation_id AND a.owner=s.owner AND a.sha256=s.sha256 WHERE s.execution_id=? AND s.artifact_id=? AND s.project_id=? AND s.conversation_id=? AND s.owner=? AND s.assessment_id=? AND s.scope_id=? ORDER BY s.id LIMIT 1001`, e.ID, artifactID, e.ProjectID, e.ConversationID, e.Owner, e.AssessmentID, e.ScopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if len(ids) > 1000 {
		return nil, fmt.Errorf("coverage source alias limit exceeded")
	}
	return ids, rows.Err()
}
