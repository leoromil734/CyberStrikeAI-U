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
	if len(req.Scope) < 1 || len(req.Scope) > 20 {
		return req, Limits{}, fmt.Errorf("授权范围须包含 1–20 个精确 HTTP(S) 来源")
	}
	scope := []string{}
	seen := map[string]bool{}
	for _, raw := range req.Scope {
		origin, err := normalizeOrigin(raw)
		if err != nil {
			return req, Limits{}, err
		}
		if !seen[origin] {
			scope = append(scope, origin)
			seen[origin] = true
		}
	}
	req.Scope = scope
	limits := DefaultLimits
	if req.MaxParallel != 0 {
		limits.MaxParallel = req.MaxParallel
	}
	if req.MaxAgents != 0 {
		limits.MaxAgents = req.MaxAgents
	}
	if req.TimeoutSeconds != 0 {
		limits.TimeoutSeconds = req.TimeoutSeconds
	}
	if limits.MaxParallel < 1 || limits.MaxParallel > 4 || limits.MaxAgents < limits.MaxParallel || limits.MaxAgents > 12 || limits.TimeoutSeconds < 60 || limits.TimeoutSeconds > 1800 {
		return req, Limits{}, fmt.Errorf("并发须为 1–4，总子 Agent 数须不小于并发且不超过 12，时限须为 60–1800 秒")
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
