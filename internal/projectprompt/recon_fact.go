package projectprompt

import "strings"

// reconSourceRequiredKeys / reconEndpointRequiredKeys / reconPhaseRequiredKeys
// 为 body 软校验字段名（大小写不敏感子串匹配）。
var reconSourceRequiredKeys = []string{"status", "raw", "unique", "incremental", "error", "alt_tried"}
var reconEndpointRequiredKeys = []string{"host", "method", "path", "runtime_status"}
var reconPhaseRequiredKeys = []string{"status", "evidence"}

// IsReconFactKey 判断 fact_key 是否为侦察账本前缀。
func IsReconFactKey(factKey string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "recon/")
}

// IsSparseReconFactBody 侦察类事实 body 缺少门禁字段时返回 true（软校验）。
func IsSparseReconFactBody(category, factKey, body string) bool {
	c := strings.ToLower(strings.TrimSpace(category))
	key := strings.ToLower(strings.TrimSpace(factKey))
	if c != "recon" && !strings.HasPrefix(key, "recon/") {
		return false
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return true
	}
	lower := strings.ToLower(body)
	var required []string
	switch {
	case strings.HasPrefix(key, "recon/source/"), strings.Contains(key, "/source/"):
		required = reconSourceRequiredKeys
	case strings.HasPrefix(key, "recon/endpoint/"), strings.Contains(key, "/endpoint/"):
		required = reconEndpointRequiredKeys
	case strings.HasPrefix(key, "recon/phase/"), strings.Contains(key, "/phase/"):
		required = reconPhaseRequiredKeys
	default:
		return !strings.Contains(lower, "status") && !strings.Contains(lower, "证据") && !strings.Contains(lower, "evidence")
	}
	for _, field := range required {
		if !strings.Contains(lower, field) {
			return true
		}
	}
	return false
}

// ReconFactBodyTemplate 按 recon fact_key 返回建议 body 骨架。
func ReconFactBodyTemplate(factKey string) string {
	key := strings.ToLower(strings.TrimSpace(factKey))
	switch {
	case strings.HasPrefix(key, "recon/source/"), strings.Contains(key, "/source/"):
		return reconSourceFactBodyTemplate
	case strings.HasPrefix(key, "recon/endpoint/"), strings.Contains(key, "/endpoint/"):
		return reconEndpointFactBodyTemplate
	case strings.HasPrefix(key, "recon/phase/"), strings.Contains(key, "/phase/"):
		return reconPhaseFactBodyTemplate
	default:
		return reconGenericFactBodyTemplate
	}
}

const reconSourceFactBodyTemplate = `status: covered|blocked|gap|not-applicable
raw: <整数>
unique: <整数>
incremental: <整数>
error: <失败原文或 none>
alt_tried: <替代来源列表或 []>
tool: <工具名>
target: <根域/主机>`

const reconEndpointFactBodyTemplate = `host: <主机>
method: <GET|POST|...>
path: </api/...>
params: <参数列表或 none>
auth_hint: <anonymous|cookie|bearer|unknown>
source_js: <来源 JS 或 page>
runtime_status: discovered|extracted|baselined|risk-mapped|verified|negated|blocked
value_reason: <价值理由>
evidence: <状态码/长度/hash 或 blocked 原因>`

const reconPhaseFactBodyTemplate = `status: pending|active|passed|blocked
evidence: <覆盖对象 + 计数 + 证据位置>
blockers: <原始错误与替代路径或 none>`

const reconGenericFactBodyTemplate = `status: covered|blocked|gap|not-applicable
evidence: <关联证据与计数>
details: <资产/资源细节>`