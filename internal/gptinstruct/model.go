package gptinstruct

import (
	"path"
	"strings"
)

// IsGPTSeriesModel 仅按模型名判定是否属于 GPT 系列。
// 不看 provider / base_url / 协议（openai_compatible 也可能挂 qwen/deepseek）。
//
// 命中示例：gpt-4o、gpt-5.6-sol、chatgpt-4o-latest、ft:gpt-4o:org:slug、azure/gpt-4.1
// 不命中：qwen3-max、deepseek-chat、claude-3-opus、o1、o3-mini
func IsGPTSeriesModel(model string) bool {
	name := normalizeModelName(model)
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "gpt-") || strings.HasPrefix(name, "chatgpt-") {
		return true
	}
	// 少数网关用下划线：gpt_4o
	if strings.HasPrefix(name, "gpt_") || strings.HasPrefix(name, "chatgpt_") {
		return true
	}
	return false
}

// normalizeModelName 抽出可判定的短模型名（去路径前缀、微调前缀）。
func normalizeModelName(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return ""
	}
	// 网关路径：openai/gpt-4o、azure/deployments/gpt-4o
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	m = path.Base(m)
	// OpenAI fine-tune：ft:gpt-4o-2024-08-06:org:name:id
	if strings.HasPrefix(m, "ft:") {
		parts := strings.Split(m, ":")
		if len(parts) >= 2 {
			m = parts[1]
		}
	}
	return strings.TrimSpace(m)
}