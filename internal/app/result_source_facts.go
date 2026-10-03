package app

import (
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
	"encoding/json"
	"fmt"
	"strings"
)

func (p *resultPipeline) saveReconSourceFact(e evidence.Execution, source recon.Source) error {
	var unique int64
	if err := p.db.QueryRow(`SELECT COUNT(*) FROM recon_record_sources WHERE source_id=?`, source.ID).Scan(&unique); err != nil {
		return err
	}
	tool := e.OutputTool()
	if source.Tool == "fofa" {
		tool = "fofa_search"
	}
	status := "covered"
	confidence := "confirmed"
	if source.State != evidence.Parsed || source.Completion != evidence.Complete {
		status = "blocked"
		confidence = "tentative"
	}
	raw := source.Stats.Records + source.Stats.Rejected
	if raw < unique {
		raw = unique
	}
	fields := map[string]interface{}{"schema_version": 2, "assessment_id": e.AssessmentID, "tool": tool, "target": "original authorized task scope (conversation:" + e.ConversationID + ")",
		"source_id": source.ID, "execution_id": e.ID, "status": status, "raw": raw, "unique": unique, "incremental": source.Inserted.Total(),
		"evidence":   "execution:" + e.ID + "; source:" + source.ID + "; artifact:" + source.ArtifactID,
		"completion": source.Completion, "inventory_records": unique, "expires_at": source.ExpiresAt,
		"notes": "服务端离线解析原件的结构化记录计数，不是HTTP请求数或目标全量覆盖。未知授权发现只作为候选。"}
	if status == "blocked" {
		reason := source.Reason
		if reason == "" {
			reason = source.State + "/" + source.Completion
		}
		fields["error"] = reason
		fields["alt_tried"] = []string{"已尝试登记同执行原件并离线解析；结果状态=" + source.State + "，实际导入记录=" + fmt.Sprint(unique)}
		fields["reason"] = reason
	}
	body, _ := json.Marshal(fields)
	key := "recon/source/" + e.AssessmentID + "/auto-" + strings.TrimPrefix(source.ID, "source-")
	if err := coverage.ValidateLedgerFact(key, string(body)); err != nil {
		return err
	}
	_, err := p.db.UpsertProjectFactPatch(&database.ProjectFact{ProjectID: e.ProjectID, FactKey: key, Category: "recon", Summary: fmt.Sprintf("%s 原件%s，%d条结构化记录，新增%d；不是覆盖结论", tool, status, unique, source.Inserted.Total()), Body: string(body), Confidence: confidence, SourceConversationID: e.ConversationID}, database.ProjectFactPatchFields{})
	return err
}
