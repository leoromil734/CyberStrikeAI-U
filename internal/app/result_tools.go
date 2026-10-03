package app

import (
	"context"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/recon"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func (p *resultPipeline) authorizedExecution(ctx context.Context, id string) (context.Context, evidence.Execution, error) {
	principal, ok := authctx.PrincipalFromContext(ctx)
	if !ok || !principal.HasPermission("monitor:read") || !p.db.UserCanAccessToolExecution(principal.UserID, principal.ScopeFor("monitor:read"), id) {
		return ctx, evidence.Execution{}, evidence.ErrDenied
	}
	conv := conversationIDFromToolCtx(ctx)
	if conv == "" {
		return ctx, evidence.Execution{}, evidence.ErrDenied
	}
	projectID, err := p.db.GetConversationProjectID(conv)
	if err != nil {
		return ctx, evidence.Execution{}, err
	}
	ctx = evidence.WithAccess(ctx, evidence.Access{ProjectID: projectID, ConversationID: conv, Owner: principal.UserID})
	e, err := p.db.ResultExecution(ctx, id)
	return ctx, e, err
}
func (p *resultPipeline) authorizedRegistry(ctx context.Context, id string) (context.Context, evidence.Execution, *evidence.Registry, error) {
	ctx, e, err := p.authorizedExecution(ctx, id)
	if err != nil {
		return ctx, e, nil, err
	}
	roots, err := p.roots(e)
	if err != nil {
		return ctx, e, nil, err
	}
	registry, err := evidence.NewRegistry(p.db, roots, evidence.DefaultMaxArtifactBytes)
	return ctx, e, registry, err
}
func resultJSON(v interface{}) (*mcp.ToolResult, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return textResult(string(body), false), nil
}
func resultRegion(args map[string]interface{}, key string) (evidence.Region, error) {
	var region evidence.Region
	value := args[key]
	body, err := json.Marshal(value)
	if err != nil {
		return region, err
	}
	if err = json.Unmarshal(body, &region); err != nil {
		return region, err
	}
	if region.ArtifactID == "" || region.Offset < 0 || region.Length < 0 || region.Length > 16384 {
		return region, fmt.Errorf("region requires artifact_id, non-negative offset and length <=16384")
	}
	return region, nil
}
func registerResultTools(server *mcp.Server, p *resultPipeline) {
	stringField := map[string]interface{}{"type": "string"}
	executionProps := func() map[string]interface{} { return map[string]interface{}{"execution_id": stringField} }
	regionSchema := map[string]interface{}{"type": "object", "properties": map[string]interface{}{"artifact_id": stringField, "offset": map[string]interface{}{"type": "integer", "minimum": 0}, "length": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 16384}}, "required": []string{"artifact_id"}}
	add := func(name, description string, props map[string]interface{}, required []string, fn mcp.ToolHandler) {
		server.RegisterTool(mcp.Tool{Name: name, ShortDescription: description, Description: description, InputSchema: map[string]interface{}{"type": "object", "properties": props, "required": required}}, fn)
	}
	props := executionProps()
	add(builtin.ToolListResultArtifacts, "按执行ID查看原件hash、大小、完整性和来源；原件正文不进入清单。", props, []string{"execution_id"}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		ctx, e, err := p.authorizedExecution(ctx, strArg(args, "execution_id"))
		if err != nil {
			return textResult("无法访问当前会话/用户绑定的执行原件", true), nil
		}
		artifacts, err := p.db.ResultArtifacts(ctx, e.ID, 100, 0)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		return resultJSON(map[string]interface{}{"execution": e, "artifacts": artifacts, "limit": 100})
	})
	props = executionProps()
	props["region"] = regionSchema
	add(builtin.ToolReadResultArtifact, "读取已登记原件的有界片段（最大16KiB）；按hash复核并遮蔽常见认证字段，不读取任意文件路径。", props, []string{"execution_id", "region"}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		ctx, e, registry, err := p.authorizedRegistry(ctx, strArg(args, "execution_id"))
		if err != nil {
			return textResult("无法访问原件或管理根不安全", true), nil
		}
		defer registry.Close()
		region, err := resultRegion(args, "region")
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		snippet, err := registry.ReadRegion(ctx, e.ID, region)
		if err != nil {
			return textResult("原件读取失败: "+evidence.ErrorCode(err), true), nil
		}
		return resultJSON(snippet)
	})
	props = executionProps()
	props["input_region"] = regionSchema
	props["output_region"] = regionSchema
	add(builtin.ToolAssembleResultEvidence, "组装原始工具输入与实际输出的最小证据。始终unverified，不执行POC，不替代原始HTTP请求、身份控制与安全边界验证。", props, []string{"execution_id", "input_region", "output_region"}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		ctx, e, registry, err := p.authorizedRegistry(ctx, strArg(args, "execution_id"))
		if err != nil {
			return textResult("无法访问原件或管理根不安全", true), nil
		}
		defer registry.Close()
		input, err := resultRegion(args, "input_region")
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		output, err := resultRegion(args, "output_region")
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		assembled, err := registry.Assemble(ctx, e.ID, input, output)
		if err != nil {
			return textResult("证据组装失败: "+evidence.ErrorCode(err), true), nil
		}
		return resultJSON(assembled)
	})
	props = executionProps()
	props["kind"] = map[string]interface{}{"type": "string", "enum": []string{"host", "service", "endpoint", "js", "candidate"}}
	props["offset"] = map[string]interface{}{"type": "integer", "minimum": 0}
	props["grouped"] = map[string]interface{}{"type": "boolean"}
	add(builtin.ToolQueryReconInventory, "分页查看同评估的真实发现库存/来源（上限100）；grouped返回保留路由参数值的端点/JS工作组。只是候选，不授权新扫描。", props, []string{"execution_id"}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		ctx, e, err := p.authorizedExecution(ctx, strArg(args, "execution_id"))
		if err != nil {
			return textResult("无法访问当前执行库存", true), nil
		}
		offset := intArg(args, "offset", 0)
		if offset < 0 || offset > 100000 {
			return textResult("offset 必须为0-100000", true), nil
		}
		counts, err := p.db.ReconInventoryCounts(ctx, e.ID)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		sources, err := p.db.ReconSources(ctx, e.ID, 100, 0, time.Now())
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		if args["grouped"] == true {
			groups, capped, err := p.db.AssessmentDiscoveryGroupsForExecution(ctx, e.ID)
			if err != nil {
				return textResult(err.Error(), true), nil
			}
			total := len(groups)
			if offset > total {
				offset = total
			}
			end := offset + 100
			if end > total {
				end = total
			}
			return resultJSON(map[string]interface{}{"groups": groups[offset:end], "total_groups": total, "comparison_capped": capped, "inventory": counts, "sources": sources, "candidate_only": true, "limit": 100, "offset": offset})
		}
		records, err := p.db.ReconInventory(ctx, e.ID, strArg(args, "kind"), 100, offset)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		return resultJSON(map[string]interface{}{"records": records, "inventory": counts, "sources": sources, "candidate_only": true, "limit": 100, "offset": offset})
	})
	props = executionProps()
	props["relative_path"] = stringField
	props["location"] = map[string]interface{}{"type": "string", "enum": []string{"execution", "js", "reduction"}, "default": "execution"}
	props["format"] = map[string]interface{}{"type": "string", "enum": []string{"json", "jsonl", "csv", "text", "xml"}}
	add(builtin.ToolRegisterResultArtifact, "登记同执行托管目录中的机读原件并离线解析。文件须先输出到CSAI_ARTIFACT_DIR；不接受绝对路径或stdout自称的work_dir，通用exec不猜扫描器。", props, []string{"execution_id", "relative_path", "format"}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		ctx, e, registry, err := p.authorizedRegistry(ctx, strArg(args, "execution_id"))
		if err != nil {
			return textResult("无法访问当前执行管理根", true), nil
		}
		defer registry.Close()
		if e.Status == "running" || e.Status == "queued" {
			return textResult("执行尚未结束，不能登记仍在写入的原件", true), nil
		}
		var ingestState string
		_ = p.db.QueryRow(`SELECT state FROM result_ingestion_jobs WHERE execution_id=? AND project_id=? AND conversation_id=? AND owner=?`, e.ID, e.ProjectID, e.ConversationID, e.Owner).Scan(&ingestState)
		if ingestState == "pending" {
			return textResult("自动原件处理尚未结束，请稍后登记额外原件", true), nil
		}
		relative := strArg(args, "relative_path")
		if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "..") || strings.ContainsAny(relative, ":\x00") {
			return textResult("relative_path 必须为安全相对路径", true), nil
		}
		roots, err := p.roots(e)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		location := strArg(args, "location")
		if location == "" {
			location = "execution"
		}
		path := ""
		for _, root := range roots {
			if location == "execution" && filepath.Base(root.Path) == e.ID || location == "reduction" && filepath.Base(root.Path) == "trunc" || location == "js" && filepath.Base(root.Path) == "execution-"+e.ID {
				path = filepath.Join(root.Path, relative)
				break
			}
		}
		if path == "" {
			return textResult("该执行尚无对应托管目录", true), nil
		}
		if e.Tool == "exec" || e.Tool == "execute" {
			if original, err := p.db.GetToolExecution(e.ID); err == nil && original != nil {
				e.ParserTool = trustedDirectScanner(original.Arguments)
			}
		}
		processor := recon.Processor{Store: p.db, Artifacts: registry, MaxReturnedRecords: 100, Limits: recon.Limits{MaxRecords: 100000}}
		report, err := processor.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{{Path: path, Kind: "output", Format: strArg(args, "format"), Completion: e.Completion}}, ExpiresAt: e.FinishedAt.Add(24 * time.Hour)})
		if err != nil {
			return textResult("原件登记/离线解析失败", true), nil
		}
		if err = p.importRecon(ctx, e, report); err != nil {
			return textResult("库存已保留，资产/候选投影不完整", true), nil
		}
		state, reason := "complete", ""
		if len(report.ArtifactErrors) > 0 {
			state, reason = "partial", "one or more registered originals were rejected"
		}
		for _, source := range report.Sources {
			if source.State != evidence.Parsed || source.Completion != evidence.Complete {
				state, reason = "partial", "registered source remains partial or unsupported"
			}
		}
		_ = p.db.SetResultIngestionState(ctx, e, state, reason)
		return resultJSON(compactResultReport(report))
	})
}
func trustedDirectScanner(args map[string]interface{}) string {
	command, _ := args["command"].(string)
	if command == "" || strings.ContainsAny(command, ";&|><`$\r\n") {
		return ""
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	name := filepath.Base(fields[0])
	if name == "httpx-pd" {
		name = "httpx"
	}
	if reconTool(name) {
		return name
	}
	return ""
}
