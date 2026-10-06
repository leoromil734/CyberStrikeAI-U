package vulnquality

import "strings"

// CompleteRecordArgs fills mechanical record fields when a finding already has
// a real evidence body. It does not invent evidence, a title, or a severity.
// Anonymous configuration leaks can also receive a boundary statement taken
// from the description the model already wrote.
func CompleteRecordArgs(args map[string]interface{}) {
	if args == nil {
		return
	}
	evidence := strings.TrimSpace(stringField(args, "evidence"))
	if len([]rune(evidence)) < 40 {
		return
	}
	if strings.TrimSpace(stringField(args, "title")) == "" {
		if title := firstSentence(stringField(args, "description")); title != "" {
			args["title"] = title
		}
	}
	target := strings.TrimSpace(stringField(args, "target"))
	if target == "" {
		target = "evidence 中的目标"
	}
	if strings.TrimSpace(stringField(args, "reproduction_steps")) == "" {
		args["reproduction_steps"] = "1. 向 " + target + " 重放 evidence 中的完整请求。\n2. 将响应与 evidence 里的实际输出对照，确认同一状态码和敏感内容。"
	}
	if strings.TrimSpace(stringField(args, "vulnerability_type")) == "" {
		if impactClass := strings.TrimSpace(stringField(args, "impact_class")); impactClass != "" {
			args["vulnerability_type"] = impactClass
		} else {
			args["vulnerability_type"] = "information_disclosure"
		}
	}
	if strings.TrimSpace(stringField(args, "impact")) == "" {
		if description := strings.TrimSpace(stringField(args, "description")); description != "" {
			args["impact"] = description
		}
	}
	if strings.TrimSpace(stringField(args, "description")) == "" {
		if title := strings.TrimSpace(stringField(args, "title")); title != "" {
			args["description"] = title
		}
	}
	if strings.TrimSpace(stringField(args, "recommendation")) == "" {
		args["recommendation"] = "禁止匿名访问该入口，并移除生产环境中暴露的配置、绝对路径和版本信息。"
	}
	if hasValidationObject(args) || !anonymousFinding(args) {
		return
	}
	if strings.TrimSpace(stringField(args, "attacker_starting_state")) == "" {
		args["attacker_starting_state"] = "未认证的匿名访问者"
	}
	if _, present := args["credential_compromise_required"]; !present {
		args["credential_compromise_required"] = false
	}
	if strings.TrimSpace(stringField(args, "security_boundary_crossed")) == "" {
		args["security_boundary_crossed"] = "未登录即可读取服务端配置、路径或源码信息"
	}
	if _, present := args["additional_authority_proven"]; !present {
		args["additional_authority_proven"] = true
	}
	if strings.TrimSpace(stringField(args, "control_comparison")) == "" {
		comparison := strings.TrimSpace(stringField(args, "description"))
		if comparison == "" {
			comparison = "evidence 中的请求与实际输出构成对照"
		}
		args["control_comparison"] = comparison
	}
}

func stringField(args map[string]interface{}, key string) string {
	value, _ := args[key].(string)
	return value
}

func hasValidationObject(args map[string]interface{}) bool {
	_, ok := args["validation"]
	return ok
}

func anonymousFinding(args map[string]interface{}) bool {
	text := strings.ToLower(stringField(args, "title") + "\n" + stringField(args, "description") + "\n" + stringField(args, "preconditions"))
	return strings.Contains(text, "匿名") || strings.Contains(text, "无需登录") || strings.Contains(text, "unauthenticated")
}

func firstSentence(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if i := strings.IndexAny(text, "\n。"); i > 0 {
		text = strings.TrimSpace(text[:i])
	}
	runes := []rune(text)
	if len(runes) > 80 {
		return string(runes[:80])
	}
	return text
}
