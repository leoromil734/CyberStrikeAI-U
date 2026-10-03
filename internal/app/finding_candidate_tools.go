package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
)

func candidateEvidenceRefs(db *database.DB, ctx context.Context, projectID, conversationID string, raw interface{}) ([]string, error) {
	refs := []string{}
	switch values := raw.(type) {
	case []interface{}:
		for _, v := range values {
			if s, ok := v.(string); ok {
				refs = append(refs, s)
			} else {
				return nil, fmt.Errorf("evidence_refs must contain strings")
			}
		}
	case []string:
		refs = append(refs, values...)
	case nil:
		return refs, nil
	default:
		return nil, fmt.Errorf("evidence_refs must be an array")
	}
	if len(refs) > 32 {
		return nil, fmt.Errorf("at most 32 evidence references")
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, "execution:") {
			return nil, fmt.Errorf("candidate evidence_refs require execution:<id>")
		}
		id := strings.TrimPrefix(ref, "execution:")
		if strings.Contains(id, ":") || id == "" {
			return nil, fmt.Errorf("candidate evidence_refs currently require execution:<id>")
		}
		var conv string
		if err := db.QueryRow(`SELECT COALESCE(conversation_id,'') FROM tool_executions WHERE id=?`, id).Scan(&conv); err != nil {
			return nil, fmt.Errorf("evidence execution not found")
		}
		if conv != conversationID {
			pid, err := db.GetConversationProjectID(conv)
			if err != nil || pid != projectID {
				return nil, fmt.Errorf("evidence belongs to another project")
			}
		}
		if principal, ok := authctx.PrincipalFromContext(ctx); ok && (!principal.HasPermission("monitor:read") || !db.UserCanAccessToolExecution(principal.UserID, principal.ScopeFor("monitor:read"), id)) {
			return nil, fmt.Errorf("no access to evidence execution")
		}
	}
	return refs, nil
}

func saveCandidateFromArgs(db *database.DB, ctx context.Context, args map[string]interface{}) (*database.FindingCandidate, error) {
	projectID, err := projectIDFromConversation(db, ctx)
	if err != nil {
		return nil, err
	}
	conv := conversationIDFromToolCtx(ctx)
	refs, err := candidateEvidenceRefs(db, ctx, projectID, conv, args["evidence_refs"])
	if err != nil {
		return nil, err
	}
	status := strings.TrimSpace(strArg(args, "status"))
	if status == "" {
		status = "tentative"
	}
	impact := strings.TrimSpace(strArg(args, "impact_class"))
	if impact == "" {
		impact = "unknown"
	}
	priority := 50
	if impact == "public_metadata" {
		priority = 10
	}
	if status == "validated" {
		v, err := db.GetVulnerability(strArg(args, "related_vulnerability_id"))
		if err != nil || !canAccessVulnerability(v, conv, projectID) {
			return nil, fmt.Errorf("formal finding not accessible in current project")
		}
		if principal, ok := authctx.PrincipalFromContext(ctx); ok && (!principal.HasPermission("vulnerability:read") || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("vulnerability:read"), "vulnerability", v.ID)) {
			return nil, fmt.Errorf("no access to related finding")
		}
	}
	assessmentID := strArg(args, "assessment_id")
	if assessmentID == "" {
		if run, err := db.LatestAssessmentRun(conv); err == nil && run != nil {
			assessmentID = run.AssessmentID
		}
	}
	c := &database.FindingCandidate{ProjectID: projectID, ConversationID: conv, AssessmentID: assessmentID,
		Target: strings.TrimSpace(strArg(args, "target")), Title: strings.TrimSpace(strArg(args, "title")), RiskFamily: strings.TrimSpace(strArg(args, "risk_family")),
		ImpactClass: impact, Status: status, Summary: strArg(args, "summary"), Reason: strArg(args, "reason"), EvidenceRefs: refs,
		RelatedVulnerabilityID: strArg(args, "related_vulnerability_id"), Priority: priority}
	if err := db.UpsertFindingCandidate(c); err != nil {
		return nil, err
	}
	return c, nil
}

func registerFindingCandidateTools(server *mcp.Server, db *database.DB) {
	props := map[string]interface{}{}
	for _, key := range []string{"assessment_id", "target", "title", "risk_family", "impact_class", "summary", "reason", "related_vulnerability_id"} {
		props[key] = map[string]interface{}{"type": "string"}
	}
	props["status"] = map[string]interface{}{"type": "string", "enum": []string{"observed", "tentative", "waiting", "blocked", "rejected", "validated"}, "description": "validated 仅表示关联已正式记录的 finding，不是重新执行 POC 或独立复核"}
	props["evidence_refs"] = map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "maxItems": 32, "description": "execution:<id>，原件和大正文不复制进候选"}
	server.RegisterTool(mcp.Tool{Name: builtin.ToolUpsertFindingCandidate, ShortDescription: "记录/更新漏洞候选与观察", Description: "扫描/版本/JS 命中先进入候选。公开元数据使用 observed，不增加正式漏洞计数。只有实际证明安全边界并通过 record_vulnerability 后才关联 finding；本工具不执行任何 POC。", InputSchema: map[string]interface{}{"type": "object", "properties": props, "required": []string{"target", "title", "risk_family", "summary"}}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		c, err := saveCandidateFromArgs(db, ctx, args)
		if err != nil {
			return textResult("错误: "+err.Error(), true), nil
		}
		body, _ := json.Marshal(c)
		return textResult(string(body), false), nil
	})
	server.RegisterTool(mcp.Tool{Name: builtin.ToolListFindingCandidates, ShortDescription: "查看项目待验证候选", Description: "按当前项目分页上限列出候选/观察。优先处理就绪的高价值候选；waiting/blocked 不阻止独立 ready 项。候选不等于漏洞。", InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"status": props["status"]}}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		rows, err := db.ListFindingCandidates(projectID, strArg(args, "status"), 50)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		body, _ := json.Marshal(map[string]interface{}{"candidates": rows, "count": len(rows), "limit": 50, "candidate_only": true})
		return textResult(string(body), false), nil
	})
}
