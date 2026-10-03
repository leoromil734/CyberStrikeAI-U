package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/openai"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

var aiChannelProbeSlots = make(chan struct{}, 3)

func aiChannelProbeHash(channel config.AIChannelConfig) string {
	// Including credentials detects key rotation, but the fingerprint is never
	// returned to clients. Test bodies and tokens are not stored.
	body, _ := json.Marshal(channel)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func runAIChannelProbe(ctx context.Context, id string, channel config.AIChannelConfig, logger *zap.Logger) database.AIChannelProbe {
	started := time.Now()
	result := database.AIChannelProbe{ChannelID: id, ChannelName: channel.Name, Model: channel.Model, Status: "failed", TestedAt: started, ConfigHash: aiChannelProbeHash(channel)}
	if strings.TrimSpace(channel.APIKey) == "" || strings.TrimSpace(channel.Model) == "" {
		result.Error = "配置不完整：请填写 API Key 和模型型号"
		return result
	}
	oa := channel.ToOpenAIConfig()
	client := openai.NewClient(&oa, nil, logger)
	payload := map[string]interface{}{"model": oa.Model, "stream": true, "messages": []map[string]string{{"role": "user", "content": "Reply with OK only."}}, "max_completion_tokens": 256}
	_, err := client.ChatCompletionStream(ctx, payload, func(delta string) error {
		if delta != "" && result.TTFTMs == nil {
			ms := time.Since(started).Milliseconds()
			result.TTFTMs = &ms
		}
		return nil
	})
	result.LatencyMs = time.Since(started).Milliseconds()
	if err != nil {
		var apiErr *openai.APIError
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			result.Error = "测试超时（45 秒），未完成流式响应"
		case errors.Is(ctx.Err(), context.Canceled):
			result.Error = "测试已取消"
		case errors.As(err, &apiErr):
			result.Error = fmt.Sprintf("上游返回 HTTP %d，请检查模型权限、配额与服务地址", apiErr.StatusCode)
		default:
			result.Error = "流式连接失败，请检查服务地址、TLS、网络或上游响应格式"
		}
		return result
	}
	if result.TTFTMs == nil {
		result.Error = "未收到有效文本 token；请确认模型支持流式文本生成"
		return result
	}
	result.Success, result.Status = true, "ready"
	return result
}

func (h *ConfigHandler) TestAIChannel(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "测试记录存储不可用"})
		return
	}
	id := c.Param("id")
	h.mu.RLock()
	channel, ok := h.config.AI.Channels[id]
	h.mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "通道不存在，请先保存配置"})
		return
	}
	select {
	case aiChannelProbeSlots <- struct{}{}:
		defer func() { <-aiChannelProbeSlots }()
	default:
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "已有三个模型正在测试，请稍后重试"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()
	result := runAIChannelProbe(ctx, id, channel, h.logger)
	if err := h.db.SaveAIChannelProbe(result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "测试完成但结果保存失败，请重试"})
		return
	}
	h.mu.RLock()
	current, exists := h.config.AI.Channels[id]
	result.Stale = !exists || aiChannelProbeHash(current) != result.ConfigHash
	h.mu.RUnlock()
	c.JSON(http.StatusOK, result)
}

func (h *ConfigHandler) GetAIChannelProbes(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "测试记录存储不可用"})
		return
	}
	stored, err := h.db.ListAIChannelProbes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取测试结果失败"})
		return
	}
	results := make(map[string]database.AIChannelProbe)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, channel := range h.config.AI.Channels {
		if result, ok := stored[id]; ok {
			result.Stale = result.ConfigHash != aiChannelProbeHash(channel)
			results[id] = result
		}
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}
