package database

import (
	"context"
	"cyberstrike-ai/internal/coverage"
	"fmt"
)

// This server-internal query is used only for delivery gating after the caller
// has authorized the conversation. It never exposes original bodies or paths.
func (db *DB) AssessmentDiscoveryGroups(projectID, conversationID, assessmentID string) ([]coverage.DiscoveryGroup, bool, error) {
	rows, err := db.Query(`SELECT id,kind,raw_url,method,owner,scope_id FROM recon_inventory WHERE project_id=? AND conversation_id=? AND assessment_id=? AND kind IN ('endpoint','js') ORDER BY id LIMIT 200001`, projectID, conversationID, assessmentID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	members := []coverage.DiscoveryMember{}
	for rows.Next() {
		var m coverage.DiscoveryMember
		if err := rows.Scan(&m.ID, &m.Kind, &m.RawURL, &m.Method, &m.Owner, &m.ScopeID); err != nil {
			return nil, false, err
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	capped := len(members) > 200000
	if capped {
		members = members[:200000]
	}
	return coverage.GroupDiscoveries(members), capped, nil
}

func (db *DB) AssessmentDiscoveryGroupsForExecution(ctx context.Context, id string) ([]coverage.DiscoveryGroup, bool, error) {
	e, err := db.ResultExecution(ctx, id)
	if err != nil {
		return nil, false, err
	}
	rows, err := db.QueryContext(ctx, `SELECT id,kind,raw_url,method,owner,scope_id FROM recon_inventory WHERE project_id=? AND conversation_id=? AND assessment_id=? AND owner=? AND scope_id=? AND kind IN ('endpoint','js') ORDER BY id LIMIT 200001`, e.ProjectID, e.ConversationID, e.AssessmentID, e.Owner, e.ScopeID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	members := []coverage.DiscoveryMember{}
	for rows.Next() {
		var m coverage.DiscoveryMember
		if err := rows.Scan(&m.ID, &m.Kind, &m.RawURL, &m.Method, &m.Owner, &m.ScopeID); err != nil {
			return nil, false, err
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	capped := len(members) > 200000
	if capped {
		members = members[:200000]
	}
	return coverage.GroupDiscoveries(members), capped, nil
}

type AssessmentSourceMetadata struct {
	ID          string
	ExecutionID string
	ArtifactID  string
	Tool        string
	State       string
	Completion  string
	Reason      string
	Unique      int64
	ExpiresAtMS int64
}

func (db *DB) AssessmentReconSources(projectID, conversationID, assessmentID string) ([]AssessmentSourceMetadata, error) {
	rows, err := db.Query(`SELECT s.id,s.execution_id,s.artifact_id,s.tool,s.state,s.completion,s.reason,s.expires_at_ms,COUNT(p.record_id) FROM recon_sources s LEFT JOIN recon_record_sources p ON p.source_id=s.id WHERE s.project_id=? AND s.conversation_id=? AND s.assessment_id=? GROUP BY s.id,s.execution_id,s.artifact_id,s.tool,s.state,s.completion,s.reason,s.expires_at_ms ORDER BY s.id LIMIT 2001`, projectID, conversationID, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssessmentSourceMetadata{}
	for rows.Next() {
		var s AssessmentSourceMetadata
		if err := rows.Scan(&s.ID, &s.ExecutionID, &s.ArtifactID, &s.Tool, &s.State, &s.Completion, &s.Reason, &s.ExpiresAtMS, &s.Unique); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(out) > 2000 {
		return nil, fmt.Errorf("source comparison limit exceeded; assessment remains incomplete")
	}
	return out, rows.Err()
}
