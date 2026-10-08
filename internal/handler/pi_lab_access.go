package handler

import (
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

type piLabReadScope struct {
	session  security.Session
	allowed  bool
	projects map[string]bool
}

// A platform run contains project evidence. Ownership alone must not retain
// access after the user loses access to that project. Probe history remains an
// independently owned resource, preserving the previous contract.
func (h *PILabHandler) canReadRun(c *gin.Context, run pilab.Run) bool {
	if run.Mode != pilab.ModePlatform {
		return true
	}
	if h.platform == nil || h.platform.db == nil || h.platform.auth == nil || run.ProjectID == "" {
		return false
	}
	const key = "piLabProjectReadScope"
	var scope *piLabReadScope
	if cached, ok := c.Get(key); ok {
		scope, _ = cached.(*piLabReadScope)
	}
	if scope == nil {
		scope = &piLabReadScope{projects: map[string]bool{}}
		session, ok := security.CurrentSession(c)
		if ok {
			fresh, valid := h.platform.auth.ValidateToken(session.Token)
			scope.session = fresh
			scope.allowed = valid && fresh.UserID == session.UserID && fresh.Permissions["project:read"]
		}
		c.Set(key, scope)
	}
	if !scope.allowed {
		return false
	}
	if allowed, known := scope.projects[run.ProjectID]; known {
		return allowed
	}
	allowed := false
	if h.platform.db.UserCanAccessResource(scope.session.UserID, scope.session.ScopeFor("project:read"), "project", run.ProjectID) {
		project, err := h.platform.db.GetProject(run.ProjectID)
		allowed = err == nil && project != nil
	}
	scope.projects[run.ProjectID] = allowed
	return allowed
}

func redactedPILabCancellation(run pilab.Run) pilab.Run {
	return pilab.Run{ID: run.ID, Mode: run.Mode, Status: run.Status, CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt, Error: "任务已停止；当前账号已无权读取原项目的结果", Scope: []string{}, Agents: []pilab.Agent{}, Nodes: []pilab.Node{}, Edges: []pilab.Edge{}, Findings: []pilab.Finding{}, Skills: []string{}, ExecutionIDs: []string{}}
}
