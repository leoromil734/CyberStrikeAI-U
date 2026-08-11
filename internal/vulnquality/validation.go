// Package vulnquality 提供不依赖数据库和传输层的漏洞独立性判定。
package vulnquality

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// BoundaryValidation 描述攻击者起始权限与候选漏洞实际跨越的安全边界。
type BoundaryValidation struct {
	AttackerStartingState        string
	CredentialCompromiseRequired bool
	SecurityBoundaryCrossed      string
	AdditionalAuthorityProven    bool
	ControlComparison            string
}

// ParseBoundaryValidation 从 record_vulnerability 参数解析结构化边界证据。
// 兼容形态：
//  1. validation 为 object（map）
//  2. validation 为 JSON 字符串（含 markdown 代码块、双重编码）
//  3. 顶层扁平字段 / validation_ 前缀字段
//  4. camelCase / 常见别名键
func ParseBoundaryValidation(args map[string]interface{}) (BoundaryValidation, []string) {
	raw, ok := coerceValidationMap(args)
	if !ok {
		return BoundaryValidation{}, []string{
			"validation（独立安全边界验证对象；请传 object，或 JSON 字符串；也可扁平传 attacker_starting_state / credential_compromise_required / security_boundary_crossed / additional_authority_proven / control_comparison）",
		}
	}

	raw = normalizeValidationKeys(raw)

	v := BoundaryValidation{
		AttackerStartingState:        strings.TrimSpace(stringValue(raw, "attacker_starting_state")),
		CredentialCompromiseRequired: boolValue(raw, "credential_compromise_required"),
		SecurityBoundaryCrossed:      strings.TrimSpace(stringValue(raw, "security_boundary_crossed")),
		AdditionalAuthorityProven:    boolValue(raw, "additional_authority_proven"),
		ControlComparison:            strings.TrimSpace(stringValue(raw, "control_comparison")),
	}
	missing := make([]string, 0, 5)
	if v.AttackerStartingState == "" {
		missing = append(missing, "validation.attacker_starting_state（攻击者执行本漏洞前实际拥有的权限）")
	}
	if !boolKeyPresent(raw, "credential_compromise_required") {
		missing = append(missing, "validation.credential_compromise_required（是否预设已窃取有效凭据/会话）")
	}
	if v.SecurityBoundaryCrossed == "" {
		missing = append(missing, "validation.security_boundary_crossed（被跨越的独立安全边界）")
	}
	if !boolKeyPresent(raw, "additional_authority_proven") {
		missing = append(missing, "validation.additional_authority_proven（是否证明获得起始权限之外的能力）")
	}
	if v.ControlComparison == "" {
		missing = append(missing, "validation.control_comparison（基线与攻击请求的对照证据）")
	}
	return v, missing
}

// coerceValidationMap 将多种模型/工具调用形态归一为 map。
func coerceValidationMap(args map[string]interface{}) (map[string]interface{}, bool) {
	if args == nil {
		return nil, false
	}

	// 1) 直接嵌套 object / 可转 map 的类型
	if raw, ok := asStringKeyMap(lookupArg(args, "validation", "Validation", "boundary_validation", "boundaryValidation")); ok {
		return raw, true
	}

	// 2) validation 为 JSON 字符串（模型常把 object 序列化后传入）
	if s, ok := lookupString(args, "validation", "Validation", "boundary_validation", "boundaryValidation"); ok {
		if m, ok := parseJSONObject(s); ok {
			return m, true
		}
	}

	// 3) 扁平字段：顶层或 validation_ 前缀
	flatKeys := []string{
		"attacker_starting_state",
		"credential_compromise_required",
		"security_boundary_crossed",
		"additional_authority_proven",
		"control_comparison",
	}
	flatAliases := map[string][]string{
		"attacker_starting_state": {
			"attackerStartingState", "starting_state", "startingState", "attacker_state",
		},
		"credential_compromise_required": {
			"credentialCompromiseRequired", "requires_credential_compromise", "requiresCredentialCompromise",
		},
		"security_boundary_crossed": {
			"securityBoundaryCrossed", "boundary_crossed", "boundaryCrossed", "security_boundary",
		},
		"additional_authority_proven": {
			"additionalAuthorityProven", "authority_proven", "authorityProven", "new_authority_proven",
		},
		"control_comparison": {
			"controlComparison", "baseline_comparison", "baselineComparison", "comparison",
		},
	}

	flat := make(map[string]interface{}, len(flatKeys))
	found := 0
	for _, key := range flatKeys {
		candidates := []string{key, "validation_" + key}
		candidates = append(candidates, flatAliases[key]...)
		for _, alias := range flatAliases[key] {
			candidates = append(candidates, "validation_"+alias)
		}
		if val, ok := firstPresent(args, candidates...); ok {
			flat[key] = val
			found++
		}
	}
	if found > 0 {
		return flat, true
	}
	return nil, false
}

// normalizeValidationKeys 将 camelCase / 别名统一为 snake_case 规范键。
func normalizeValidationKeys(raw map[string]interface{}) map[string]interface{} {
	if raw == nil {
		return nil
	}
	out := make(map[string]interface{}, len(raw)+5)
	for k, v := range raw {
		out[k] = v
	}

	aliases := map[string][]string{
		"attacker_starting_state": {
			"attackerStartingState", "starting_state", "startingState", "attacker_state", "attackerState",
		},
		"credential_compromise_required": {
			"credentialCompromiseRequired", "requires_credential_compromise", "requiresCredentialCompromise",
		},
		"security_boundary_crossed": {
			"securityBoundaryCrossed", "boundary_crossed", "boundaryCrossed", "security_boundary", "securityBoundary",
		},
		"additional_authority_proven": {
			"additionalAuthorityProven", "authority_proven", "authorityProven", "new_authority_proven", "newAuthorityProven",
		},
		"control_comparison": {
			"controlComparison", "baseline_comparison", "baselineComparison", "comparison",
		},
	}
	for canonical, list := range aliases {
		if val, ok := out[canonical]; ok && val != nil && !isEmptyValue(val) {
			continue
		}
		for _, alias := range list {
			if val, ok := out[alias]; ok && val != nil && !isEmptyValue(val) {
				out[canonical] = val
				break
			}
		}
	}
	return out
}

func lookupArg(args map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if val, ok := args[key]; ok && val != nil {
			return val
		}
	}
	// 大小写不敏感兜底
	lowerWant := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		lowerWant[strings.ToLower(key)] = struct{}{}
	}
	for k, val := range args {
		if _, ok := lowerWant[strings.ToLower(k)]; ok && val != nil {
			return val
		}
	}
	return nil
}

func lookupString(args map[string]interface{}, keys ...string) (string, bool) {
	val := lookupArg(args, keys...)
	if val == nil {
		return "", false
	}
	switch t := val.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return "", false
		}
		return s, true
	case []byte:
		s := strings.TrimSpace(string(t))
		if s == "" {
			return "", false
		}
		return s, true
	case json.RawMessage:
		s := strings.TrimSpace(string(t))
		if s == "" {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

func firstPresent(args map[string]interface{}, keys ...string) (interface{}, bool) {
	for _, key := range keys {
		if val, ok := args[key]; ok && val != nil && !isEmptyValue(val) {
			return val, true
		}
	}
	// 大小写不敏感
	for _, key := range keys {
		want := strings.ToLower(key)
		for k, val := range args {
			if strings.ToLower(k) == want && val != nil && !isEmptyValue(val) {
				return val, true
			}
		}
	}
	return nil, false
}

func asStringKeyMap(v interface{}) (map[string]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	switch m := v.(type) {
	case map[string]interface{}:
		return m, true
	case map[string]string:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out, true
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				ks = fmt.Sprint(k)
			}
			out[ks] = val
		}
		return out, true
	default:
		if b, ok := v.([]byte); ok {
			return parseJSONObject(string(b))
		}
		if raw, ok := v.(json.RawMessage); ok {
			return parseJSONObject(string(raw))
		}
		// 处理 map[string]string 之外的 map-like / 结构体
		b, err := json.Marshal(v)
		if err != nil {
			return nil, false
		}
		return parseJSONObject(string(b))
	}
}

func parseJSONObject(s string) (map[string]interface{}, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}

	// 去掉 markdown 代码块
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSpace(s)
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			// 可能有 json 语言标签
			first := strings.TrimSpace(s[:nl])
			if strings.EqualFold(first, "json") || strings.EqualFold(first, "javascript") {
				s = s[nl+1:]
			}
		}
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}

	// 双重编码： "\"{...}\"" 或 "\"...\""
	for attempt := 0; attempt < 3; attempt++ {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(s), &m); err == nil && m != nil {
			return m, true
		}
		var inner string
		if err := json.Unmarshal([]byte(s), &inner); err != nil {
			break
		}
		inner = strings.TrimSpace(inner)
		if inner == "" || inner == s {
			break
		}
		s = inner
	}
	return nil, false
}

func isEmptyValue(v interface{}) bool {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) == ""
	case nil:
		return true
	default:
		return false
	}
}

// ValidateBoundary 拒绝未证明新增权限的候选，尤其是依赖已失陷会话的正常操作。
func ValidateBoundary(v BoundaryValidation) error {
	if v.AdditionalAuthorityProven {
		return nil
	}
	if v.CredentialCompromiseRequired {
		return fmt.Errorf("候选依赖已窃取/接管的有效凭据或会话，但未证明获得该身份正常权限之外的额外能力；这属于已失陷会话的既有权限，不是独立漏洞。请改记 tentative/负结果 fact，或补充跨用户、跨角色、跨租户、未授权操作等对照证据")
	}
	return fmt.Errorf("尚未证明攻击者获得起始权限之外的能力，不能记录为正式漏洞；请补充匿名/低权限基线与攻击结果的可复现差分")
}

// PrependBoundaryEvidence 把门禁输入固化到现有前置条件和证据字段，便于后续审计。
func PrependBoundaryEvidence(v BoundaryValidation, preconditions, evidence string) (string, string) {
	credentialRequired := "否"
	if v.CredentialCompromiseRequired {
		credentialRequired = "是"
	}
	boundaryPreconditions := fmt.Sprintf("攻击者起始状态: %s\n依赖已失陷的有效凭据/会话: %s", v.AttackerStartingState, credentialRequired)
	if strings.TrimSpace(preconditions) != "" {
		boundaryPreconditions += "\n" + preconditions
	}
	boundaryEvidence := fmt.Sprintf("跨越的独立安全边界: %s\n基线/攻击对照: %s", v.SecurityBoundaryCrossed, v.ControlComparison)
	if strings.TrimSpace(evidence) != "" {
		boundaryEvidence += "\n\n" + evidence
	}
	return boundaryPreconditions, boundaryEvidence
}

func stringValue(values map[string]interface{}, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch t := value.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case float64, float32, int, int64, int32, uint, uint64, bool:
		return strings.TrimSpace(fmt.Sprint(t))
	case json.Number:
		return t.String()
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return strings.TrimSpace(fmt.Sprint(t))
		}
		s := strings.TrimSpace(string(b))
		// 去掉纯字符串 JSON 引号
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			var unquoted string
			if json.Unmarshal(b, &unquoted) == nil {
				return unquoted
			}
		}
		return s
	}
}

func boolKeyPresent(values map[string]interface{}, key string) bool {
	value, ok := values[key]
	if !ok || value == nil {
		return false
	}
	_, ok = parseBool(value)
	return ok
}

func boolValue(values map[string]interface{}, key string) bool {
	value, ok := values[key]
	if !ok {
		return false
	}
	b, ok := parseBool(value)
	if !ok {
		return false
	}
	return b
}

func parseBool(value interface{}) (bool, bool) {
	switch t := value.(type) {
	case bool:
		return t, true
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		switch s {
		case "true", "1", "yes", "y", "是", "有", "on":
			return true, true
		case "false", "0", "no", "n", "否", "无", "off":
			return false, true
		default:
			if b, err := strconv.ParseBool(s); err == nil {
				return b, true
			}
			return false, false
		}
	case float64:
		return t != 0, true
	case float32:
		return t != 0, true
	case int:
		return t != 0, true
	case int64:
		return t != 0, true
	case int32:
		return t != 0, true
	case uint:
		return t != 0, true
	case uint64:
		return t != 0, true
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i != 0, true
		}
		if f, err := t.Float64(); err == nil {
			return f != 0, true
		}
		return false, false
	default:
		return false, false
	}
}