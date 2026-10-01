package handler

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyberstrike-ai/internal/security"
	"cyberstrike-ai/internal/targets"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// recordRunTargets 在运行开始时登记「本次对话跑了哪些目标」。
// 调用点与 recordConversationAIChannel 一致（各 run 入口），失败只记日志、不阻断运行。
func (h *AgentHandler) recordRunTargets(conversationID, message string) {
	if h == nil || h.db == nil {
		return
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return
	}
	// 批量任务始终从持久化的完整 task.message 提取。普通聊天则使用本轮原始请求，
	// 保留后续用户新增目标的登记；调用方不得传入角色展开后的 FinalMessage。
	original, found, err := h.db.ConversationTaskTargetInput(conversationID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("读取原始目标输入失败（跳过目标登记）", zap.String("conversationId", conversationID), zap.Error(err))
		}
		return
	}
	if found {
		message = original
	}
	list := targets.Extract(message)
	if len(list) == 0 {
		return
	}
	title, projectID, err := h.db.ConversationTargetMeta(conversationID)
	if err != nil && h.logger != nil {
		h.logger.Debug("读取对话元信息失败（目标登记继续）", zap.String("conversationId", conversationID), zap.Error(err))
	}
	recorded, err := h.db.RecordTargetRuns(conversationID, title, projectID, list, time.Now())
	if err != nil {
		if h.logger != nil {
			// 目标登记只是提示信息，失败不影响本轮对话。
			h.logger.Warn("登记目标历史失败", zap.String("conversationId", conversationID), zap.Error(err))
		}
		return
	}
	if recorded > 0 && h.logger != nil {
		h.logger.Info("登记目标历史",
			zap.String("conversationId", conversationID),
			zap.Int("recorded", recorded),
			zap.Strings("targets", list),
		)
	}
}

type checkRunTargetsRequest struct {
	// Text 是用户输入整段文字（对话内容或批量任务行），由服务端统一提取目标。
	Text string `json:"text"`
	// Targets 允许前端直接传已拆好的目标列表，两者会合并去重。
	Targets []string `json:"targets"`
}

// CheckRunTargets 检查输入里哪些目标历史上跑过，供对话页/任务管理页做提醒。
// POST /api/targets/check
func (h *AgentHandler) CheckRunTargets(c *gin.Context) {
	session, ok := targetHistorySession(c)
	if !ok {
		return
	}
	var req checkRunTargetsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	list := targets.Extract(req.Text)
	for _, item := range targets.NormalizeAll(req.Targets) {
		list = appendUniqueTarget(list, item)
	}
	if len(list) == 0 {
		c.JSON(http.StatusOK, gin.H{"targets": []string{}, "hits": []interface{}{}, "newTargets": []string{}})
		return
	}

	hits, err := h.db.CheckTargetRunsForAccess(list, session.UserID, session.Scope)
	if err != nil {
		h.logger.Error("查询目标历史失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	hitSet := make(map[string]struct{}, len(hits))
	for _, hit := range hits {
		hitSet[hit.Target] = struct{}{}
	}
	newTargets := make([]string, 0, len(list))
	for _, item := range list {
		if _, ok := hitSet[item]; !ok {
			newTargets = append(newTargets, item)
		}
	}
	c.JSON(http.StatusOK, gin.H{"targets": list, "hits": hits, "newTargets": newTargets})
}

// ListRunTargets 分页列出跑过的目标。GET /api/targets?keyword=&page=&page_size=
func (h *AgentHandler) ListRunTargets(c *gin.Context) {
	session, ok := targetHistorySession(c)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	pageSize = int(math.Max(1, math.Min(float64(pageSize), 200)))

	keyword := strings.TrimSpace(c.Query("keyword"))
	if keyword == "" {
		keyword = strings.TrimSpace(c.Query("q"))
	}
	list, total, err := h.db.ListTargetRunsForAccess(keyword, pageSize, (page-1)*pageSize, session.UserID, session.Scope)
	if err != nil {
		h.logger.Error("加载目标历史失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	c.JSON(http.StatusOK, gin.H{
		"targets":     list,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// ListRunTargetEvents 列出某个目标跑过的对话明细。GET /api/targets/:target/events
func (h *AgentHandler) ListRunTargetEvents(c *gin.Context) {
	session, ok := targetHistorySession(c)
	if !ok {
		return
	}
	target := strings.TrimSpace(c.Param("target"))
	if targets.Normalize(target) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "目标域名不合法"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	pageSize = int(math.Max(1, math.Min(float64(pageSize), 200)))

	events, total, err := h.db.ListTargetRunEventsForAccess(target, pageSize, (page-1)*pageSize, session.UserID, session.Scope)
	if err != nil {
		h.logger.Error("加载目标运行明细失败", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	c.JSON(http.StatusOK, gin.H{
		"events":      events,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// DeleteRunTarget 删除某个目标的登记（用于清理误登记的噪声目标）。DELETE /api/targets/:target
func (h *AgentHandler) DeleteRunTarget(c *gin.Context) {
	session, ok := targetHistorySession(c)
	if !ok {
		return
	}
	target := targets.Normalize(c.Param("target"))
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "目标域名不合法"})
		return
	}
	if err := h.db.DeleteTargetRunForAccess(target, session.UserID, session.Scope); err != nil {
		h.logger.Error("删除目标历史失败", zap.String("target", target), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "target": target})
}

func targetHistorySession(c *gin.Context) (security.Session, bool) {
	session, ok := security.CurrentSession(c)
	if !ok || strings.TrimSpace(session.UserID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "请先登录"})
		return session, false
	}
	return session, true
}

func appendUniqueTarget(list []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return list
	}
	for _, existing := range list {
		if existing == item {
			return list
		}
	}
	return append(list, item)
}
