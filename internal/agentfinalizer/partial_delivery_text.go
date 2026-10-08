package agentfinalizer

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	stoppedReportMaxRunes = 20000
	stoppedInlineRunes    = 240
	stoppedScopeReadLimit = 8192
	stoppedScopeItemLimit = 6
	stoppedGapScanLimit   = 64
	stoppedGapShowLimit   = 8
)

var (
	stoppedURL = regexp.MustCompile("(?i)[a-z][a-z0-9+.-]{1,20}://[^\\s<>\"'`]+")
	// Metadata can accidentally contain credentials. Do not select credential
	// fields at all; additionally suppress common credential forms in titles
	// and scope entries. Never print the untrusted suffix of such a field.
	stoppedCredential = regexp.MustCompile(`(?i)(?:\b(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|token|access_token|refresh_token|api[_-]?key|client_secret)\b|密码|口令|令牌|密钥)["']?\s*[:=：]\s*.*`)
	stoppedAuthValue  = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[a-z0-9+/_.=-]+`)
	stoppedUserInfo   = regexp.MustCompile(`[^\s:@/<>]+:[^\s@<>]+@`)
	stoppedGapRef     = regexp.MustCompile(`(?:recon/(?:assessment|phase|source|endpoint|risk|js)/[a-zA-Z0-9._/-]{1,128}|\brecon/source for (?:fofa_search|subfinder|oneforall|dnsx|httpx|naabu|nmap|gau|katana|jsapiscan|nuclei)\b|\bdiscovery-[a-f0-9]{1,64}\b|\b(?:mcp_execution|execution):[a-zA-Z0-9._-]{1,128})`)
)

// boundStoppedText limits by runes without allocating a rune slice proportional
// to a potentially huge model/database field. The original value is untouched.
func boundStoppedText(s string, limit int) (string, bool) {
	count := 0
	for offset := range s {
		if count == limit {
			return s[:offset], true
		}
		count++
	}
	return s, false
}

func appendStoppedSection(b *strings.Builder, text string, limit int) {
	// Keep complete escaped lines: truncating in the middle of an HTML entity
	// or Markdown escape would no longer be an exact metadata excerpt.
	prefix, cut := boundStoppedText(text, limit-80)
	if !cut {
		b.WriteString(text)
		return
	}
	if end := strings.LastIndex(prefix, "\n"); end >= 0 {
		prefix = prefix[:end]
	}
	b.WriteString(prefix)
	b.WriteString("\n\n（本节展示已达长度上限；其余内容未展开，不能视为已完成。完整值请核对本会话过程记录。）\n\n")
}

func reportInline(s string) string {
	s, clipped := boundStoppedText(s, 2048)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(strings.ToUpper(s), "-----BEGIN "); i >= 0 {
		s = s[:i] + "[凭据内容已隐藏]"
	}
	s = stoppedURL.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "[地址无法安全展示]"
		}
		u.User, u.RawQuery, u.Fragment, u.RawFragment = nil, "", "", ""
		u.ForceQuery = false
		return u.String()
	})
	s = stoppedUserInfo.ReplaceAllString(s, "[认证信息已隐藏]@")
	s = stoppedCredential.ReplaceAllString(s, "[敏感字段已隐藏]")
	s = stoppedAuthValue.ReplaceAllString(s, "[认证值已隐藏]")
	var short bool
	s, short = boundStoppedText(s, stoppedInlineRunes)
	if short || clipped {
		s += "…"
	}
	if s == "" {
		return "未提供"
	}
	s = html.EscapeString(s)
	s = strings.NewReplacer("\\", "\\\\", "*", "\\*", "_", "\\_", "`", "\\`", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "#", "\\#", "!", "\\!", "|", "\\|", "~", "\\~", "{", "\\{", "}", "\\}").Replace(s)
	// Render URLs as text rather than automatic links. HTML entities are parsed
	// as text, not as new Markdown/HTML syntax, by the report renderer.
	return strings.ReplaceAll(s, ":", "&#58;")
}

func writeStoppedScope(b *strings.Builder, raw string) {
	var scope struct {
		Targets []string `json:"targets"`
		Exclude []string `json:"exclude"`
	}
	if strings.TrimSpace(raw) == "" {
		b.WriteString("- 范围：登记范围未读取或未配置；请以原任务授权为准，不能从报告候选推定授权。\n")
		return
	}
	if utf8.RuneCountInString(raw) > stoppedScopeReadLimit || json.Unmarshal([]byte(raw), &scope) != nil || (len(scope.Targets) == 0 && len(scope.Exclude) == 0) {
		b.WriteString("- 范围：项目范围文本过长、格式不可读或未包含可识别的目标／排除项，无法完整核实；不回显原始配置。\n")
		return
	}
	b.WriteString("- 范围说明：以下仅摘录当前项目的登记范围，不替代本次任务授权，也不扩大原任务的 URL、路径或端口边界；其他限制和范围说明需在项目与原任务中核对。\n")
	for _, group := range []struct {
		label  string
		values []string
	}{{"登记目标", scope.Targets}, {"登记排除项", scope.Exclude}} {
		for i, value := range group.values {
			if i == stoppedScopeItemLimit {
				fmt.Fprintf(b, "- %s：其余 %d 项未展开，恢复前须核对完整范围。\n", group.label, len(group.values)-i)
				break
			}
			fmt.Fprintf(b, "- %s：%s\n", group.label, reportInline(value))
		}
	}
}

// Explain recognized gaps, not arbitrary model-written diagnostics. Only short
// record locators may be reproduced; all original checks stay on the Decision.
// This prevents provider errors, credentials and prose such as "6/6 passed"
// from becoming apparent findings while still showing actionable categories.
func writeStoppedGaps(b *strings.Builder, checks []string) {
	if len(checks) == 0 {
		b.WriteString("停止时没有保存可展开的检查诊断，具体缺口无法核实；不能把缺少诊断当作检查通过。应先核实授权范围、库存、执行证据及待完成工具。\n\n")
		return
	}
	fmt.Fprintf(b, "保留 %d 条完整检查诊断。以下仅对可识别的诊断作有界摘要，关联标识仅用于定位，不是已核验成果；原文仍在过程详情中。\n\n", len(checks))
	seen := map[string]bool{}
	shown, inspected := 0, 0
	for _, raw := range checks {
		if inspected == stoppedGapScanLimit || shown == stoppedGapShowLimit {
			break
		}
		inspected++
		raw, _ = boundStoppedText(raw, 2048)
		lower := strings.ToLower(raw)
		label := stoppedGapLabel(lower)
		if label == "" {
			continue
		}
		refs := stoppedGapRef.FindAllString(raw, 2)
		if len(refs) > 0 {
			label += " 定位记录：" + reportInline(strings.Join(refs, "；")) + "。"
		}
		if seen[label] {
			continue
		}
		seen[label] = true
		fmt.Fprintf(b, "- %s\n", label)
		shown++
	}
	if shown == 0 {
		b.WriteString("- 现有检查未能映射为可安全展示的具体缺口；请在过程详情核对原诊断，当前仍为未完成。\n")
	}
	b.WriteString("\n摘要会合并重复项并省略未识别或超限的诊断，不代表完整缺口清单；省略不减少原始检查数量。\n\n")
}

func stoppedGapLabel(check string) string {
	switch {
	case strings.Contains(check, "queued or running"), strings.Contains(check, "pending_tool"):
		return "存在排队或运行中的工具，需核对完成状态与输出。"
	case strings.Contains(check, "hitl"), strings.Contains(check, "approval"):
		return "仍有人工审批相关限制，需先核对审批和授权状态。"
	case strings.Contains(check, "original ingestion"), strings.Contains(check, "partial/unsupported source"):
		return "原始结果入库、解析或完整性仍有缺口，需核对对应执行及来源。"
	case strings.Contains(check, "independent"), strings.Contains(check, "discovery inventory"), strings.Contains(check, "automatic coverage repair blocked"), strings.Contains(check, "coverage inventory disclosure"):
		return "独立候选库存仍有未关联、未处置或无法核实的分组，不能只靠补写台账完成评估。"
	case strings.Contains(check, "recon/source"), strings.Contains(check, "reconnaissance source"), strings.Contains(check, "execution evidence"), strings.Contains(check, "actual execution"):
		return "来源或完成态执行证据缺失／不匹配，需核对实际执行与原始结果。"
	case strings.Contains(check, "endpoint_count"), strings.Contains(check, "must equal inventory count"), strings.Contains(check, "manifest"), strings.Contains(check, "assessment_id"):
		return "评估范围、清单或声明计数与独立库存尚未一致，需核对当前评估标识及库存。"
	case strings.Contains(check, "recon/js/"), strings.Contains(check, "js resource"):
		return "JavaScript 资源尚未完成展开或缺少有证据的受阻说明。"
	case strings.Contains(check, "recon/endpoint/"), strings.Contains(check, "risk unit"), strings.Contains(check, "risk_units"), strings.Contains(check, "recon/risk/"):
		return "端点基线、身份条件、风险映射或风险验证证据仍有缺口，需逐项核对。"
	case strings.Contains(check, "recon/phase/"), strings.Contains(check, "phase needs"):
		return "测试阶段缺少完成态证据或具体受阻原因。"
	case strings.Contains(check, "report"), strings.Contains(check, "candidate"), strings.Contains(check, "assistant final text"):
		return "候选报告尚未正式提交、内容不完整或未通过交付检查。"
	default:
		return ""
	}
}
