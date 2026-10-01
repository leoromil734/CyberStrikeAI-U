package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/experience"
	em "cyberstrike-ai/internal/experience/model"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ExperienceHandler struct {
	service *experience.Service
	db      *database.DB
	audit   *audit.Service
	logger  *zap.Logger
}

func NewExperienceHandler(s *experience.Service, db *database.DB, a *audit.Service, logger *zap.Logger) *ExperienceHandler {
	return &ExperienceHandler{service: s, db: db, audit: a, logger: logger}
}
func (h *ExperienceHandler) ready(c *gin.Context) bool {
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "经验记忆功能已关闭"})
		return false
	}
	return true
}
func experienceContext(c *gin.Context) context.Context {
	if _, ok := authctx.PrincipalFromContext(c.Request.Context()); ok {
		return c.Request.Context()
	}
	s, ok := security.CurrentSession(c)
	if !ok {
		return c.Request.Context()
	}
	return authctx.WithPrincipal(c.Request.Context(), authctx.NewPrincipalWithScopes(s.UserID, s.Username, s.Scope, s.Permissions, s.PermissionScopes))
}
func (h *ExperienceHandler) fail(c *gin.Context, err error) {
	code := http.StatusInternalServerError
	message := "经验记忆处理失败"
	switch {
	case errors.Is(err, experience.ErrDenied):
		code = http.StatusForbidden
		message = "无权操作该经验或证据"
	case errors.Is(err, database.ErrExperienceNotFound):
		code = http.StatusNotFound
		message = "经验不存在或不可访问"
	case errors.Is(err, database.ErrExperienceConflict):
		code = http.StatusConflict
		message = "经验版本已变化，请刷新后重试"
	case errors.Is(err, experience.ErrInvalid):
		code = http.StatusBadRequest
		message = err.Error()
	default:
		if h.logger != nil {
			h.logger.Warn("经验 API 操作失败", zap.Error(err))
		}
	}
	c.JSON(code, gin.H{"error": message})
}
func experienceBind(c *gin.Context, out interface{}) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 320*1024)
	if err := c.ShouldBindJSON(out); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误或超过大小限制"})
		return false
	}
	return true
}
func (h *ExperienceHandler) record(c *gin.Context, action, id string) {
	if h.audit != nil {
		h.audit.Record(c, audit.Entry{Category: "experience", Action: action, ResourceType: "experience", ResourceID: id, Message: "经验记忆操作", Detail: map[string]interface{}{"id": id}})
	}
}

func (h *ExperienceHandler) List(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	items, err := h.service.List(experienceContext(c), c.Query("project_id"), c.Query("status"), c.Query("kind"), c.Query("query"), limit, offset)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "limit": limit, "offset": offset})
}
func (h *ExperienceHandler) Get(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	d, err := h.service.Get(experienceContext(c), c.Param("id"), c.Query("project_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, d)
}
func (h *ExperienceHandler) Evidence(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	data, err := h.service.Evidence(experienceContext(c), c.Param("id"), c.Param("executionId"), c.Query("project_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, data)
}

func (h *ExperienceHandler) Create(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var p em.Proposal
	if !experienceBind(c, &p) {
		return
	}
	e, err := h.service.Propose(experienceContext(c), p)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.record(c, "propose", e.ID)
	c.JSON(http.StatusCreated, e)
}
func (h *ExperienceHandler) Revise(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var body struct {
		em.Proposal
		Revision int `json:"revision"`
	}
	if !experienceBind(c, &body) {
		return
	}
	e, err := h.service.Revise(experienceContext(c), c.Param("id"), body.Revision, body.Proposal)
	if err != nil {
		h.fail(c, err)
		return
	}
	h.record(c, "revise", e.ID)
	c.JSON(http.StatusOK, e)
}
func (h *ExperienceHandler) Review(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var r em.Review
	if !experienceBind(c, &r) {
		return
	}
	if err := h.service.Review(experienceContext(c), c.Param("id"), r); err != nil {
		h.fail(c, err)
		return
	}
	h.record(c, "review", c.Param("id"))
	c.JSON(http.StatusOK, gin.H{"reviewed": true})
}
func (h *ExperienceHandler) Search(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	var q em.Search
	if !experienceBind(c, &q) {
		return
	}
	matches, err := h.service.Search(experienceContext(c), q)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"matches": matches})
}
func (h *ExperienceHandler) Outcome(c *gin.Context)          { h.outcome(c, false) }
func (h *ExperienceHandler) ConfirmedOutcome(c *gin.Context) { h.outcome(c, true) }
func (h *ExperienceHandler) outcome(c *gin.Context, confirmed bool) {
	if !h.ready(c) {
		return
	}
	var o em.Outcome
	if !experienceBind(c, &o) {
		return
	}
	o.EntryID = c.Param("id")
	if err := h.service.Outcome(experienceContext(c), o, confirmed); err != nil {
		h.fail(c, err)
		return
	}
	h.record(c, "outcome", o.EntryID)
	c.JSON(http.StatusOK, gin.H{"recorded": true})
}
func (h *ExperienceHandler) History(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	ctx := experienceContext(c)
	a, err := h.service.Access(ctx, "experience:read", c.Query("project_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	e, err := h.db.GetExperience(c.Param("id"), a)
	if err != nil {
		h.fail(c, err)
		return
	}
	// Historical versions may contain private content removed before sharing.
	if !a.Global && a.UserID != e.OwnerUserID {
		h.fail(c, experience.ErrDenied)
		return
	}
	versions, err := h.db.ExperienceRevisionHistory(e.ID)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revisions": versions})
}
func (h *ExperienceHandler) ExportSkill(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	b, name, err := h.service.ExportSkill(experienceContext(c), c.Param("id"), c.Query("project_id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	h.record(c, "export_skill", c.Param("id"))
	c.Header("Content-Disposition", "attachment; filename="+strconv.Quote(name))
	c.Data(http.StatusOK, "application/zip", b)
}
func (h *ExperienceHandler) LearningEvents(c *gin.Context) {
	if !h.ready(c) {
		return
	}
	a, err := h.service.Access(experienceContext(c), "experience:review", "")
	if err != nil || !a.Global {
		h.fail(c, experience.ErrDenied)
		return
	}
	stats, err := h.db.ExperienceQueueStats()
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"queue": stats})
}
