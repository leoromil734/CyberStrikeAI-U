package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/project"

	"go.uber.org/zap"
)

func projectConversationID(ctx context.Context) string {
	if id := strings.TrimSpace(agent.ConversationIDFromContext(ctx)); id != "" {
		return id
	}
	return strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
}

func projectIDFromConversation(db *database.DB, ctx context.Context) (string, error) {
	convID := projectConversationID(ctx)
	if convID == "" {
		return "", fmt.Errorf("无法确定当前对话，请在对话上下文中使用项目事实工具")
	}
	pid, err := db.GetConversationProjectID(convID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(pid) == "" {
		return "", fmt.Errorf("当前对话未绑定项目，请先在对话中选择项目或创建带项目的对话")
	}
	return pid, nil
}

func textResult(msg string, isErr bool) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: msg}},
		IsError: isErr,
	}
}

// registerProjectFactTools 注册项目黑板 MCP 工具。
func registerProjectFactTools(mcpServer *mcp.Server, db *database.DB, cfg *config.Config, logger *zap.Logger) {
	if db == nil || cfg == nil || !cfg.Project.Enabled {
		if logger != nil {
			logger.Info("项目黑板工具未注册（未启用）")
		}
		return
	}

	upsertTool := mcp.Tool{
		Name: builtin.ToolUpsertProjectFact,
		Description: "写入或更新项目黑板事实，用于跨会话沉淀可复现上下文（非正式漏洞条目；可交付漏洞另用 record_vulnerability）。" +
			"边渗透边记录：每确认新认知（端口/入口/凭据/可利用点）后立即调用，同 fact_key 覆盖更新，勿等会话结束。" +
			"禁止仅写结论：summary 须含什么+在哪+如何验证；body 须含复现或账本字段。" +
			"发现类 fact_key 为 finding|chain|exploit|poc/<slug>；环境类 target|auth|infra|business/<slug>；" +
			"侦察账本 recon/source|endpoint|phase|asset|js/<slug>（category=recon）；v2 用 recon/{kind}/{assessment_id}/...，正文 assessment_id 与 key 一致，优先 body_fields。" +
			"source 的 raw/unique/incremental 是真实整数，原始输出用 raw_output，covered 必须有 evidence；工具执行 success 不是覆盖终态。" +
			"评估清单 schema_version=2、mode=comprehensive、status=active/completed，填写真实 scope_kind。endpoint_count/js_count/risk_unit_count 由宿主在覆盖检查时按本轮账本事实自动推导，无需手写或同步；兼容旧计数但不作为收尾门槛。缺 scope_kind 的 active 仅保存启动记录，不能通过收尾门禁；基线、risk_units 与证据要求不变。" +
			"原始 URL/库存明细留在 query_recon_inventory 与结果工件，不要逐行复制成 fact；仅记录新的可复用结论与必要证据。" +
			"禁止为了结项而为历史 URL 批量套用 N/A/negated 或虚构逐项实测证据；事实额度用完仅暂停事实补写，继续可执行的实际验证、原件保存与漏洞记录，最终报告如实保留未完成范围。" +
			"同 fact_key 覆盖更新。需当前对话已绑定项目。",
		ShortDescription: "写入/更新项目事实（含 recon 账本）",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{
					"type":        "string",
					"description": "项目内唯一 key：target/primary_domain；v2 用 recon/assessment/{id}、recon/source/{id}/{tool}/{target_id}、recon/phase/{id}/{phase}、recon/endpoint/{id}/{endpoint_id}；旧 recon/source/{tool}/{target} 仅兼容既有笔记",
				},
				"category": map[string]interface{}{
					"type":        "string",
					"description": "target | auth | infra | business | recon | finding | chain | exploit | poc | note；创建默认 note，更新时省略或留空保留原值",
					"enum":        []string{"target", "auth", "infra", "business", "recon", "finding", "chain", "exploit", "poc", "note"},
				},
				"summary": map[string]interface{}{
					"type":        "string",
					"description": "索引用一行：结论 + 位置 + 触发/验证要点（勿仅写「存在 XSS」等空话）",
				},
				"body": map[string]interface{}{
					"type": "string",
					"description": "完整详情（仅 get_project_fact 返回）。发现/利用类须含攻击链与请求响应；" +
						"recon/source 须含 status/raw/unique/incremental/error/alt_tried/evidence，raw 为真实整数，文本用 raw_output；版本化账本带 assessment_id；recon/endpoint 须含 host/method/path/runtime_status 等；body 带 endpoint_url/method/assessment_id 时自动生成稳定端点 key，以返回 fact_key 为准。" +
						"更新已有 fact_key 时若省略或留空 body，将保留库中已有 body（可只改 summary）。",
				},
				"body_fields": ledgerStructuredBodySchema(),
				"confidence": map[string]interface{}{
					"type":        "string",
					"description": "confirmed | tentative | deprecated；创建默认 tentative，更新时省略或留空保留原值",
					"enum":        []string{"confirmed", "tentative", "deprecated"},
				},
				"pinned": map[string]interface{}{
					"type":        "boolean",
					"description": "是否优先出现在黑板索引；更新时省略保留原值，明确 false 取消置顶",
				},
				"related_vulnerability_id": map[string]interface{}{
					"type":        "string",
					"description": "可选：关联的漏洞记录 ID；更新时省略保留原值，传空字符串清空关联",
				},
				"links": map[string]interface{}{
					"type":        "array",
					"description": "可选：关系边（from → 当前 fact）。finding 至少 1 条 {from:target/*, type:discovered_on}；finding 上记录 exploit 用 {from:exploit/*, type:exploits}。省略保留已有边；传 [] 清空全部关系边。",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"from": map[string]interface{}{
								"type":        "string",
								"description": "来源 fact_key：存储为 from → 当前 fact",
							},
							"type": map[string]interface{}{
								"type":        "string",
								"description": "depends_on | leads_to | enables | exploits | discovered_on | contains | part_of | supports",
							},
							"confidence": map[string]interface{}{
								"type":        "string",
								"description": "confirmed | tentative | deprecated",
							},
						},
						"required": []string{"from", "type"},
					},
				},
			},
			"required": []string{"fact_key", "summary"},
		},
	}

	mcpServer.RegisterTool(upsertTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		factKey, _ := args["fact_key"].(string)
		summary, _ := args["summary"].(string)
		if strings.TrimSpace(factKey) == "" || strings.TrimSpace(summary) == "" {
			return textResult("错误: fact_key 与 summary 必填", true), nil
		}
		if len([]rune(summary)) > cfg.Project.FactSummaryMaxRunesEffective() {
			return textResult(fmt.Sprintf("错误: summary 过长（最多 %d 字）", cfg.Project.FactSummaryMaxRunesEffective()), true), nil
		}
		body, err := projectFactBodyFromArguments(args)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		factKey = strings.TrimSpace(factKey)
		var ledgerNotes []string
		if strings.TrimSpace(strArg(args, "confidence")) != "deprecated" {
			body, ledgerNotes, err = coverage.NormalizeLedgerWrite(factKey, body)
			if err != nil {
				return ledgerWriteValidationError(ctx, factKey, err, args), nil
			}
		}
		canonicalKey, err := coverage.CanonicalEndpointFactKey(factKey, body)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		existing, err := db.GetProjectFactByKey(projectID, canonicalKey)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return textResult("错误: 读取已有事实失败: "+err.Error(), true), nil
		}
		effectiveBody, effectiveConfidence := body, strings.TrimSpace(strArg(args, "confidence"))
		if existing != nil {
			if strings.TrimSpace(effectiveBody) == "" {
				effectiveBody = existing.Body
			}
			if effectiveConfidence == "" {
				effectiveConfidence = existing.Confidence
			}
		}
		// Validate the effective patch before any mutation. Deprecating a corrupt
		// historical record must remain possible; restoring it requires repair.
		if effectiveConfidence != "deprecated" {
			if err := coverage.ValidateLedgerFact(factKey, effectiveBody); err != nil {
				return ledgerWriteValidationError(ctx, factKey, err, args), nil
			}
			if canonicalKey != factKey {
				if err := coverage.ValidateLedgerFact(canonicalKey, effectiveBody); err != nil {
					return ledgerWriteValidationError(ctx, factKey, err, args), nil
				}
			}
		}
		factKey = canonicalKey
		f := &database.ProjectFact{
			ProjectID:              projectID,
			FactKey:                factKey,
			Category:               strArg(args, "category"),
			Summary:                summary,
			Body:                   body,
			Confidence:             strArg(args, "confidence"),
			Pinned:                 boolArg(args, "pinned"),
			RelatedVulnerabilityID: strArg(args, "related_vulnerability_id"),
		}
		if convID := projectConversationID(ctx); convID != "" {
			f.SourceConversationID = convID
		}
		_, pinnedSet := args["pinned"]
		_, relatedVulnerabilityIDSet := args["related_vulnerability_id"]
		if projectFactMutationIsNoop(existing, f, args) {
			return textResult(fmt.Sprintf("事实内容未变化，复用已保存记录；本次不占用写入额度。\nfact_key: %s\nid: %s\nconfidence: %s", existing.FactKey, existing.ID, existing.Confidence), false), nil
		}
		if _, hasLinks := args["links"]; hasLinks {
			if _, err := project.ParseFactLinkInputs(args["links"]); err != nil {
				return textResult("错误: "+err.Error(), true), nil
			}
		}
		// Schema errors and exact repeats cannot consume the mutation quota.
		// A quota failure is a recoverable tool response, not a run error.
		if err := mcp.AdmitProjectFactWrite(ctx, cfg.Agent.MaxFactWritesPerRunEffective()); err != nil {
			if errors.Is(err, mcp.ErrFactWriteBudget) {
				return textResult(err.Error(), true), nil
			}
			return textResult(err.Error(), true), err
		}
		created, err := db.UpsertProjectFactPatch(f, database.ProjectFactPatchFields{
			PinnedSet:                 pinnedSet,
			RelatedVulnerabilityIDSet: relatedVulnerabilityIDSet,
		})
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if _, hasLinks := args["links"]; hasLinks {
			linkInputs, err := project.ParseFactLinkInputs(args["links"])
			if err != nil {
				return textResult("错误: "+err.Error(), true), nil
			}
			convID := projectConversationID(ctx)
			if err := project.PersistFactLinksFromParsed(db, projectID, created.FactKey, convID, linkInputs, true); err != nil {
				return textResult("错误: 保存关系边失败: "+err.Error(), true), nil
			}
			created, _ = db.GetProjectFactByKey(projectID, created.FactKey)
		} else if parsed := project.ParseLinksFromBody(created.Body); len(parsed) > 0 {
			if err := project.PersistFactIncomingLinks(db, projectID, created.FactKey, parsed, true); err != nil {
				return textResult("错误: 从 body 解析边失败: "+err.Error(), true), nil
			}
			created, _ = db.GetProjectFactByKey(projectID, created.FactKey)
		}
		msg := fmt.Sprintf("事实已保存。\nfact_key: %s\nid: %s\nconfidence: %s", created.FactKey, created.ID, created.Confidence)
		if len(ledgerNotes) > 0 {
			msg += "\n账本提示:\n- " + strings.Join(ledgerNotes, "\n- ")
		}
		if in, _ := db.ListIncomingProjectFactEdges(projectID, created.FactKey); len(in) > 0 {
			msg += "\n关系边: " + project.FormatFactLinksText(in)
		}
		if warn := project.SparseBodyWarningIfNeeded(f.Category, f.FactKey, f.Body); warn != "" {
			msg += warn
		}
		return textResult(msg, false), nil
	})

	getTool := mcp.Tool{
		Name:             builtin.ToolGetProjectFact,
		Description:      "按 fact_key 获取项目事实完整 body 与元数据。摘要不足时必须调用本工具，禁止臆造细节。",
		ShortDescription: "按 key 获取事实详情",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{"type": "string", "description": "事实 key"},
			},
			"required": []string{"fact_key"},
		},
	}
	mcpServer.RegisterTool(getTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		key := strings.TrimSpace(strArg(args, "fact_key"))
		if key == "" {
			return textResult("错误: fact_key 必填", true), nil
		}
		f, err := db.GetProjectFactByKey(projectID, key)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		msg := fmt.Sprintf("fact_key: %s\ncategory: %s\nconfidence: %s\nsummary: %s\nupdated_at: %s",
			f.FactKey, f.Category, f.Confidence, f.Summary, f.UpdatedAt.Format("2006-01-02 15:04:05"))
		if f.RelatedVulnerabilityID != "" {
			msg += fmt.Sprintf("\nrelated_vulnerability_id: %s", f.RelatedVulnerabilityID)
		}
		if f.SourceConversationID != "" {
			msg += fmt.Sprintf("\nsource_conversation_id: %s", f.SourceConversationID)
		}
		if in, _ := db.ListIncomingProjectFactEdges(projectID, f.FactKey); len(in) > 0 {
			msg += "\n关系边（from → 本 fact）:\n"
			for _, e := range in {
				msg += fmt.Sprintf("- %s ← %s (%s)\n", e.EdgeType, e.SourceFactKey, e.Confidence)
			}
		}
		if out, _ := db.ListOutgoingProjectFactEdges(projectID, f.FactKey); len(out) > 0 {
			msg += "指向其他事实:\n"
			for _, e := range out {
				msg += fmt.Sprintf("- %s → %s (%s)\n", e.EdgeType, e.TargetFactKey, e.Confidence)
			}
		}
		msg += "\n\n--- body ---\n" + f.Body
		if warn := project.SparseBodyWarningIfNeeded(f.Category, f.FactKey, f.Body); warn != "" {
			msg += warn
		}
		return textResult(msg, false), nil
	})

	listTool := mcp.Tool{
		Name:             builtin.ToolListProjectFacts,
		Description:      "列出当前项目的事实（分页）。",
		ShortDescription: "列出项目事实",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"category":   map[string]interface{}{"type": "string"},
				"confidence": map[string]interface{}{"type": "string"},
				"limit":      map[string]interface{}{"type": "integer"},
				"offset":     map[string]interface{}{"type": "integer"},
			},
		},
	}
	mcpServer.RegisterTool(listTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		limit := intArg(args, "limit", 50)
		offset := intArg(args, "offset", 0)
		filter := database.ProjectFactListFilter{
			Category:   strArg(args, "category"),
			Confidence: strArg(args, "confidence"),
		}
		list, err := db.ListProjectFacts(projectID, filter, limit, offset)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("共 %d 条（limit=%d offset=%d）:\n", len(list), limit, offset))
		for _, f := range list {
			b.WriteString(fmt.Sprintf("- [%s] %s — %s (%s)\n", f.FactKey, f.Category, f.Summary, f.Confidence))
		}
		return textResult(b.String(), false), nil
	})

	searchTool := mcp.Tool{
		Name:             builtin.ToolSearchProjectFacts,
		Description:      "按关键词搜索项目事实（summary/body/fact_key）。",
		ShortDescription: "搜索项目事实",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query":  map[string]interface{}{"type": "string"},
				"limit":  map[string]interface{}{"type": "integer"},
				"offset": map[string]interface{}{"type": "integer"},
			},
			"required": []string{"query"},
		},
	}
	mcpServer.RegisterTool(searchTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		q := strings.TrimSpace(strArg(args, "query"))
		if q == "" {
			return textResult("错误: query 必填", true), nil
		}
		list, err := db.ListProjectFacts(projectID, database.ProjectFactListFilter{Search: q}, intArg(args, "limit", 30), intArg(args, "offset", 0))
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("搜索 \"%s\" 命中 %d 条:\n", q, len(list)))
		for _, f := range list {
			b.WriteString(fmt.Sprintf("- [%s] %s — %s\n", f.FactKey, f.Category, f.Summary))
		}
		return textResult(b.String(), false), nil
	})

	deprecateTool := mcp.Tool{
		Name:             builtin.ToolDeprecateProjectFact,
		Description:      "将事实标记为 deprecated，从黑板索引中排除。",
		ShortDescription: "废弃项目事实",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{"type": "string"},
			},
			"required": []string{"fact_key"},
		},
	}
	mcpServer.RegisterTool(deprecateTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		key := strings.TrimSpace(strArg(args, "fact_key"))
		if err := db.DeprecateProjectFact(projectID, key); err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		return textResult("事实已标记为 deprecated: "+key, false), nil
	})

	restoreTool := mcp.Tool{
		Name:             builtin.ToolRestoreProjectFact,
		Description:      "将已废弃（deprecated）的事实恢复为 tentative 或 confirmed，重新参与黑板索引。",
		ShortDescription: "恢复已废弃的项目事实",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{"type": "string"},
				"confidence": map[string]interface{}{
					"type":        "string",
					"description": "恢复后的置信度：tentative（默认）或 confirmed",
					"enum":        []string{"tentative", "confirmed"},
				},
			},
			"required": []string{"fact_key"},
		},
	}
	mcpServer.RegisterTool(restoreTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		key := strings.TrimSpace(strArg(args, "fact_key"))
		if key == "" {
			return textResult("错误: fact_key 必填", true), nil
		}
		conf := strArg(args, "confidence")
		fact, err := db.GetProjectFactByKey(projectID, key)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if err := coverage.ValidateLedgerFact(key, fact.Body); err != nil {
			return textResult("错误: 请先修复账本再恢复: "+err.Error(), true), nil
		}
		if err := db.RestoreProjectFact(projectID, key, conf); err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		if conf == "" {
			conf = "tentative"
		}
		return textResult(fmt.Sprintf("事实已恢复为 %s: %s", conf, key), false), nil
	})

	if logger != nil {
		logger.Debug("项目黑板 MCP 工具注册成功")
	}
}

// projectFactBodyFromArguments serializes the full object without guessing or
// coercing any evidence/count. An empty text body retains existing patch semantics.
func projectFactBodyFromArguments(args map[string]interface{}) (string, error) {
	body := strArg(args, "body")
	fields, supplied := args["body_fields"]
	if !supplied {
		return body, nil
	}
	if strings.TrimSpace(body) != "" {
		return "", fmt.Errorf("body 与 body_fields 只能提供一个完整正文")
	}
	object, ok := fields.(map[string]interface{})
	if !ok || object == nil {
		return "", fmt.Errorf("body_fields 必须是完整对象")
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("body_fields 无法序列化: %w", err)
	}
	return string(encoded), nil
}

func strArg(args map[string]interface{}, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func boolArg(args map[string]interface{}, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func intArg(args map[string]interface{}, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return def
	}
}
