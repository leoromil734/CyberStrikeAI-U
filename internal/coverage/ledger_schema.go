package coverage

// LedgerBodySchema exposes the writable machine contract to tool callers rather
// than hiding enums in a Markdown reference. Additional observation fields stay
// compatible; this schema does not authorize or confirm a test.
func LedgerBodySchema() map[string]interface{} {
	stringField := func(desc string) map[string]interface{} {
		return map[string]interface{}{"type": "string", "description": desc}
	}
	countField := map[string]interface{}{"type": "integer", "minimum": 0}
	return map[string]interface{}{"type": "object", "properties": map[string]interface{}{
		"assessment_id":  stringField("当前评估标识，须与 key 一致"),
		"schema_version": map[string]interface{}{"type": "integer", "enum": []int{2}},
		"mode":           map[string]interface{}{"type": "string", "enum": []string{"comprehensive"}},
		"scope_kind":     map[string]interface{}{"type": "string", "enum": []string{"root-domain", "single-url", "ip", "asset-list"}},
		"status":         map[string]interface{}{"type": "string", "enum": []string{"pending", "active", "completed", "passed", "blocked", "covered", "not-applicable", "queued", "fetched", "analyzed", "expanded", "tentative", "gap", "waiting", "negated"}},
		"phase":          map[string]interface{}{"type": "string", "enum": phases},
		"runtime_status": map[string]interface{}{"type": "string", "enum": []string{"discovered", "extracted", "baselined", "risk-mapped", "verified", "negated", "blocked"}},
		"raw":            countField, "unique": countField, "incremental": countField,
		"endpoint_count": countField, "js_count": countField, "risk_unit_count": countField,
		"tool": stringField("真实工具名称；jsluice/历史 jsapiscan 为静态发现来源，不能单独验证 HTTP 风险"), "target": stringField("原始授权目标，不规范化扩大范围；HTTP 原件来源须同时填写精确 URL 与 method"),
		"host": stringField("端点主机"), "method": stringField("实际 HTTP 方法"), "path": stringField("实际路径或有依据的模板"),
		"endpoint_url":        stringField("不含 userinfo 的 HTTP(S) 原始URL；路径、端口及路由参数值保持不变"),
		"inventory_group_key": stringField("query_recon_inventory(grouped=true) 返回的独立工作组 key；必须匹配原始 URL/方法/路由参数"),
		"url":                 stringField("JS/source map 的原始资源URL"),
		"execution_id":        stringField("原件对应的真实执行ID"),
		"source_id":           stringField("离线解析来源ID"),
		"endpoint_key":        stringField("本评估已登记的 recon/endpoint/... 键"),
		"risk_family":         stringField("风险类别；HTTP 请求响应原件只支持 covered 的 http-baseline/http-response 观测，不自动证明其他风险或 negated 安全结论；不得以基线替换已有风险单元"), "identity": stringField("匿名/用户A/用户B/角色，不能贴口令"),
		"risk_units": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "完整风险事实键，不是风险名称或裸字符串"},
		"evidence":   stringField("execution_id/原件与可复核的实际结果定位；不得编造"),
		"blockers":   stringField("原始阻断错误/条件及替代结果"),
		"error":      stringField("原始失败原因"), "reason": stringField("具体 blocked/N/A 依据"),
		"raw_output": stringField("原始文本或原件引用，不能写入计数字段"),
	}}
}
