package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/security"

	"github.com/gin-gonic/gin"
)

type PILabModelResolver func(string) (pilab.Model, string, error)

type PILabHandler struct {
	manager *pilab.Manager
	resolve PILabModelResolver
}

func NewPILabHandler(manager *pilab.Manager, resolve PILabModelResolver) *PILabHandler {
	return &PILabHandler{manager: manager, resolve: resolve}
}

// ResolvePILabModel takes a read-locked value snapshot. Credentials are never
// returned by a PI HTTP endpoint and configuration edits cannot mutate a run.
func (h *ConfigHandler) ResolvePILabModel(channelID string) (pilab.Model, string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.config == nil {
		return pilab.Model{}, "", fmt.Errorf("模型配置未加载")
	}
	if strings.TrimSpace(channelID) != "" {
		if _, ok := h.config.AI.Channels[config.NormalizeAIChannelID(channelID)]; !ok {
			return pilab.Model{}, "", fmt.Errorf("所选模型通道不存在")
		}
	}
	oa, id, ok := h.config.ResolveAIChannel(channelID)
	if !ok {
		return pilab.Model{}, "", fmt.Errorf("所选模型通道不存在")
	}
	provider := strings.ToLower(strings.TrimSpace(oa.Provider))
	if provider == "" || provider == "openai_compatible" {
		provider = "openai"
	}
	if provider == "anthropic" {
		provider = "claude"
	}
	contextWindow := oa.MaxTotalTokens
	if contextWindow <= 0 {
		contextWindow = 128000
	}
	maxTokens := oa.MaxCompletionTokens
	if maxTokens <= 0 {
		maxTokens = 8192
	}
	model := pilab.Model{Provider: provider, BaseURL: strings.TrimSpace(oa.BaseURL), APIKey: oa.APIKey, ID: oa.Model, ContextWindow: contextWindow, MaxTokens: maxTokens}
	model = pilab.NormalizeModel(model)
	return model, id, pilab.ValidateModel(model)
}

// Even administrators only see their own experiments. PI experiments do not
// inherit a production project's sharing/assignment scope.
func piLabOwner(c *gin.Context) (string, bool) {
	c.Header("Cache-Control", "no-store")
	session, ok := security.CurrentSession(c)
	if !ok || strings.TrimSpace(session.UserID) == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
		return "", false
	}
	if !security.SessionHasPermission(c, "agent:execute") {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "缺少 Agent 执行权限"})
		return "", false
	}
	return session.UserID, true
}

func piLabError(c *gin.Context, err error) {
	code := http.StatusBadRequest
	switch {
	case errors.Is(err, pilab.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, pilab.ErrBusy):
		code = http.StatusConflict
	case errors.Is(err, pilab.ErrStorage):
		code = http.StatusInternalServerError
	case errors.Is(err, pilab.ErrDisabled), errors.Is(err, pilab.ErrUnavailable):
		code = http.StatusServiceUnavailable
	}
	c.JSON(code, gin.H{"error": err.Error()})
}

func (h *PILabHandler) Status(c *gin.Context) {
	if _, ok := piLabOwner(c); !ok {
		return
	}
	c.JSON(http.StatusOK, h.manager.Status(c.Request.Context()))
}

func (h *PILabHandler) List(c *gin.Context) {
	owner, ok := piLabOwner(c)
	if !ok {
		return
	}
	runs, err := h.manager.List(owner)
	if err != nil {
		piLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"runs": runs})
}

func (h *PILabHandler) Create(c *gin.Context) {
	owner, ok := piLabOwner(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)
	var req pilab.CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PI 请求格式无效或超过 32 KiB"})
		return
	}
	validated, _, err := pilab.ValidateRequest(req)
	if err != nil {
		piLabError(c, err)
		return
	}
	if h.resolve == nil {
		piLabError(c, pilab.ErrUnavailable)
		return
	}
	model, channel, err := h.resolve(validated.AIChannel)
	if err != nil {
		piLabError(c, err)
		return
	}
	validated.AIChannel = channel
	run, err := h.manager.Create(owner, validated, model)
	if err != nil {
		piLabError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, run)
}

func (h *PILabHandler) Get(c *gin.Context) {
	owner, ok := piLabOwner(c)
	if !ok {
		return
	}
	run, err := h.manager.Get(owner, c.Param("id"))
	if err != nil {
		piLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, run)
}

func (h *PILabHandler) Cancel(c *gin.Context) {
	owner, ok := piLabOwner(c)
	if !ok {
		return
	}
	run, err := h.manager.Cancel(owner, c.Param("id"))
	if err != nil {
		piLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, run)
}

func (h *PILabHandler) Events(c *gin.Context) {
	owner, ok := piLabOwner(c)
	if !ok {
		return
	}
	after, err := strconv.ParseInt(c.DefaultQuery("after", "0"), 10, 64)
	if err != nil || after < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "事件游标无效"})
		return
	}
	page, err := h.manager.Events(owner, c.Param("id"), after)
	if err != nil {
		piLabError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}
