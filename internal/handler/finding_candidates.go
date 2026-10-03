package handler

import (
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// Candidate observations are a separate list and never change formal finding
// totals. Permissions are checked here as well as in the route middleware.
func (h *ProjectHandler) ListFindingCandidates(c *gin.Context) {
	projectID := c.Param("id")
	session, ok := security.CurrentSession(c)
	if !ok || !security.SessionHasPermission(c, "project:read") || !h.db.UserCanAccessResource(session.UserID, session.Scope, "project", projectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权读取该项目候选"})
		return
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if err != nil || limit < 1 || limit > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "limit 必须为 1-100"})
		return
	}
	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offset < 0 || offset > 100000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset 无效"})
		return
	}
	rows, err := h.db.ListFindingCandidatesPage(projectID, c.Query("status"), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取候选列表"})
		return
	}
	out := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		out = append(out, gin.H{"id": row.ID, "title": row.Title, "target": row.Target, "risk_family": row.RiskFamily, "impact_class": row.ImpactClass, "state": row.Status, "status": row.Status, "priority": row.Priority, "reason": row.Reason, "summary": row.Summary, "evidence_refs": row.EvidenceRefs, "updated_at": row.UpdatedAt, "related_vulnerability_id": row.RelatedVulnerabilityID})
	}
	c.JSON(http.StatusOK, gin.H{"candidates": out, "limit": limit, "offset": offset, "candidate_only": true})
}
