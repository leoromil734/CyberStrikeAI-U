package experience

import (
	"context"
	"database/sql"
	"errors"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
)

func (s *Service) loadEvidenceExecution(ctx context.Context, id string) (*mcp.ToolExecution, string, error) {
	p, ok := authctx.PrincipalFromContext(ctx)
	if !ok || !p.HasPermission("monitor:read") {
		return nil, "", ErrDenied
	}
	archive, err := s.db.GetExperienceExecutionArchive(id)
	if err == nil {
		allowed := p.ScopeFor("monitor:read") == database.RBACScopeAll
		if !allowed && archive.Execution.OwnerUserID == p.UserID {
			allowed = archive.ProjectID == "" || (p.HasPermission("project:read") && s.db.UserCanAccessResource(p.UserID, p.ScopeFor("project:read"), "project", archive.ProjectID))
		}
		if !allowed && archive.Execution.ConversationID != "" && p.HasPermission("chat:read") {
			allowed = s.db.UserCanAccessResource(p.UserID, p.ScopeFor("chat:read"), "conversation", archive.Execution.ConversationID)
		}
		if !allowed {
			return nil, "", ErrDenied
		}
		return archive.Execution, archive.ProjectID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	if !s.db.UserCanAccessToolExecution(p.UserID, p.ScopeFor("monitor:read"), id) {
		return nil, "", ErrDenied
	}
	exec, err := s.db.GetToolExecution(id)
	if err != nil {
		return nil, "", err
	}
	var project sql.NullString
	if exec.ConversationID != "" {
		if err := s.db.QueryRow(`SELECT project_id FROM conversations WHERE id = ?`, exec.ConversationID).Scan(&project); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, "", err
		}
	}
	return exec, project.String, nil
}

// Evidence is separately authorized: sharing a method never grants access to
// its raw source evidence, even when the monitor retention policy removes it.
func (s *Service) Evidence(ctx context.Context, entryID, executionID, projectID string) (interface{}, error) {
	a, err := s.Access(ctx, "experience:read", projectID)
	if err != nil {
		return nil, err
	}
	e, err := s.db.GetExperience(entryID, a)
	if err != nil {
		return nil, err
	}
	if !s.db.ExperienceEvidenceContains(e.ID, e.Revision, executionID) {
		return nil, ErrDenied
	}
	exec, _, err := s.loadEvidenceExecution(ctx, executionID)
	if err != nil {
		return nil, err
	}
	archive, err := s.db.GetExperienceExecutionArchive(executionID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"execution": exec, "content_hash": archive.ContentHash, "archived": true}, nil
}
