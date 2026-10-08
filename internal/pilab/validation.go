package pilab

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func ValidateRequest(req CreateRequest) (CreateRequest, Limits, error) {
	req.Title, req.Prompt = strings.TrimSpace(req.Title), strings.TrimSpace(req.Prompt)
	if !req.Authorized {
		return req, Limits{}, fmt.Errorf("必须确认拥有所填范围的测试授权")
	}
	if req.Title == "" || utf8.RuneCountInString(req.Title) > 120 {
		return req, Limits{}, fmt.Errorf("标题须为 1–120 个字符")
	}
	if req.Prompt == "" || len(req.Prompt) > 16384 {
		return req, Limits{}, fmt.Errorf("测试需求不能为空且不能超过 16 KiB")
	}
	if len(req.AIChannel) > 128 {
		return req, Limits{}, fmt.Errorf("模型通道标识过长")
	}
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = ModeProbe
	} // Preserve existing callers and history.
	if req.Mode != ModeProbe && req.Mode != ModePlatform {
		return req, Limits{}, fmt.Errorf("PI 模式无效")
	}
	if len(req.Scope) < 1 || len(req.Scope) > 20 {
		return req, Limits{}, fmt.Errorf("授权范围须包含 1–20 项")
	}
	limits := DefaultLimits
	caps := Limits{MaxParallel: 4, MaxAgents: 12, TimeoutSeconds: 1800, MaxTurns: 20, MaxToolCalls: 256}
	if req.Mode == ModePlatform {
		req.ProjectID, req.Role = strings.TrimSpace(req.ProjectID), strings.TrimSpace(req.Role)
		if req.ProjectID == "" || len(req.ProjectID) > 128 {
			return req, Limits{}, fmt.Errorf("正式模式必须选择一个可访问的项目")
		}
		if req.Role == "" {
			req.Role = "渗透测试"
		}
		if req.Role != "渗透测试" {
			return req, Limits{}, fmt.Errorf("正式模式使用本项目的渗透测试角色")
		}
		limits, caps = DefaultPlatformLimits, PlatformLimitCaps
	}
	scope := []string{}
	seen := map[string]bool{}
	for _, raw := range req.Scope {
		value := strings.TrimSpace(raw)
		if req.Mode == ModeProbe {
			var err error
			value, err = normalizeOrigin(raw)
			if err != nil {
				return req, Limits{}, err
			}
		} else if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return req, Limits{}, fmt.Errorf("每项授权范围须为非空单行文本，最多 1024 字节")
		}
		if !seen[value] {
			scope = append(scope, value)
			seen[value] = true
		}
	}
	req.Scope = scope
	if req.MaxParallel != 0 {
		limits.MaxParallel = req.MaxParallel
	}
	if req.MaxAgents != 0 {
		limits.MaxAgents = req.MaxAgents
	}
	if req.TimeoutSeconds != 0 {
		limits.TimeoutSeconds = req.TimeoutSeconds
	}
	if req.MaxTurns != 0 {
		limits.MaxTurns = req.MaxTurns
	}
	if req.MaxToolCalls != 0 {
		limits.MaxToolCalls = req.MaxToolCalls
	}
	if limits.MaxParallel < 1 || limits.MaxParallel > caps.MaxParallel || limits.MaxAgents < limits.MaxParallel || limits.MaxAgents > caps.MaxAgents || limits.TimeoutSeconds < 60 || limits.TimeoutSeconds > caps.TimeoutSeconds || limits.MaxTurns < 1 || limits.MaxTurns > caps.MaxTurns || limits.MaxToolCalls < 1 || limits.MaxToolCalls > caps.MaxToolCalls {
		return req, Limits{}, fmt.Errorf("PI 预算超出模式上限：并发 %d、子 Agent %d、时限 %d 秒、模型 %d 轮、工具 %d 次；子 Agent 数不能小于并发", caps.MaxParallel, caps.MaxAgents, caps.TimeoutSeconds, caps.MaxTurns, caps.MaxToolCalls)
	}
	return req, limits, nil
}

func normalizeOrigin(raw string) (string, error) {
	invalid := fmt.Errorf("授权范围仅接受完整的精确来源，例如 https://example.com:8443；不支持路径、通配符、私网、本机或链路本地地址")
	raw = strings.TrimSpace(raw)
	if len(raw) > 512 {
		return "", invalid
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", invalid
	}
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, "*%\\ \t\r\n") || strings.HasSuffix(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" || host == "metadata" {
		return "", invalid
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return "", invalid
		}
	} else {
		// Reject WHATWG's alternative IPv4 spellings and require ASCII DNS names.
		parts := strings.Split(host, ".")
		last := parts[len(parts)-1]
		if _, err := strconv.ParseUint(last, 0, 32); err == nil {
			return "", invalid
		}
		if _, err := strconv.ParseUint(last, 10, 32); err == nil {
			return "", invalid
		}
		for _, part := range parts {
			if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return "", invalid
			}
			for _, c := range part {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", invalid
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", invalid
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, nil
}

// NormalizeModel applies PI-specific output budgets without mutating the shared channel.
func NormalizeModel(model Model) Model {
	if model.BaseURL == "" {
		if model.Provider == "claude" {
			model.BaseURL = "https://api.anthropic.com"
		} else {
			model.BaseURL = "https://api.openai.com/v1"
		}
	}
	if model.ContextWindow == 0 {
		model.ContextWindow = 128000
	}
	if model.MaxTokens == 0 {
		model.MaxTokens = 8192
	}
	if model.MaxTokens > 32768 {
		model.MaxTokens = 32768
	}
	if model.ContextWindow > 0 && model.MaxTokens > model.ContextWindow {
		model.MaxTokens = model.ContextWindow
	}
	return model
}

func ValidateModel(model Model) error {
	model = NormalizeModel(model)
	if model.ContextWindow < 1024 || model.ContextWindow > 2000000 || model.MaxTokens < 1 {
		return fmt.Errorf("所选模型上下文预算无效，PI 支持 1024–2000000 tokens")
	}
	if strings.TrimSpace(model.ID) == "" || len(model.ID) > 256 || strings.TrimSpace(model.APIKey) == "" {
		return fmt.Errorf("所选模型通道缺少模型型号或 API Key")
	}
	if model.Provider != "openai" && model.Provider != "claude" {
		return fmt.Errorf("PI 试验目前支持 OpenAI 兼容通道和 Claude 通道")
	}
	if model.BaseURL != "" {
		u, err := url.Parse(model.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("模型通道地址格式无效，请在系统设置中修正")
		}
	}
	return nil
}
