package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/mcp"
)

var recordingValidationAttempts = struct {
	sync.Mutex
	entries map[string]validationAttempt
}{entries: make(map[string]validationAttempt)}

type validationAttempt struct {
	count int
	at    time.Time
}

func ledgerStructuredBodySchema() map[string]interface{} {
	schema := coverage.LedgerBodySchema()
	schema["description"] = "完整结构化正文，与非空 body 二选一。字段不是补丁；来源计数必须真实且 incremental <= unique <= raw。使用已列出的状态/阶段枚举与完整风险事实引用。"
	return schema
}

// Compact diagnostics preserve validation strength while avoiding a full copy
// of the same evidence guide on every rejection. The caller still gets the
// exact original reason plus machine-readable repair fields.
func recordingValidationError(ctx context.Context, tool, code, message string, args map[string]interface{}, fields []string, expected interface{}) *mcp.ToolResult {
	encoded, _ := json.Marshal(args)
	fingerprint := sha256.Sum256(append([]byte(conversationIDFromToolCtx(ctx)+"\x00"+tool+"\x00"+code+"\x00"), encoded...))
	key := string(fingerprint[:])
	now := time.Now()
	recordingValidationAttempts.Lock()
	if len(recordingValidationAttempts.entries) > 2048 {
		for k, v := range recordingValidationAttempts.entries {
			if now.Sub(v.at) > 10*time.Minute {
				delete(recordingValidationAttempts.entries, k)
			}
		}
		if len(recordingValidationAttempts.entries) > 2048 {
			recordingValidationAttempts.entries = make(map[string]validationAttempt)
		}
	}
	attempt := recordingValidationAttempts.entries[key]
	if now.Sub(attempt.at) > 10*time.Minute {
		attempt.count = 0
	}
	attempt.count++
	attempt.at = now
	recordingValidationAttempts.entries[key] = attempt
	recordingValidationAttempts.Unlock()
	payload := map[string]interface{}{"status": "validation_error", "code": code, "error": message, "fields": fields,
		"save_performed": false, "identical_attempts": attempt.count, "repeat_unchanged_allowed": false,
		"repair_required": attempt.count >= 3, "expected": expected}
	body, _ := json.Marshal(payload)
	return textResult(string(body), true)
}

func ledgerWriteValidationError(ctx context.Context, key string, err error, args map[string]interface{}) *mcp.ToolResult {
	fields := []string{"body_fields"}
	expected := map[string]interface{}{"input": "structured body_fields", "counts": "incremental <= unique <= raw"}
	msg := err.Error()
	if strings.Contains(msg, "runtime_status") {
		fields = []string{"body_fields.runtime_status"}
		expected["values"] = []string{"discovered", "extracted", "baselined", "risk-mapped", "verified", "negated", "blocked"}
	} else if strings.Contains(msg, "phase") {
		fields = []string{"body_fields.phase", "body_fields.status"}
		expected["phases"] = []string{"recon_sources", "asset_ranking", "frontend_api", "auth_workflows", "risk_matrix", "gap_review"}
	} else if strings.Contains(msg, "risk_units") {
		fields = []string{"body_fields.risk_units"}
		expected["reference"] = "recon/risk/<assessment_id>/<unit>"
	} else if strings.Contains(msg, "counts") {
		fields = []string{"body_fields.raw", "body_fields.unique", "body_fields.incremental"}
	} else if strings.Contains(msg, "evidence") || strings.Contains(msg, "blockers") {
		fields = []string{"body_fields.evidence", "body_fields.blockers"}
		expected["evidence"] = "actual execution reference and original result/details"
	}
	return recordingValidationError(ctx, "upsert_project_fact", "invalid_ledger", "错误: 账本未保存: "+msg, args, fields, expected)
}
