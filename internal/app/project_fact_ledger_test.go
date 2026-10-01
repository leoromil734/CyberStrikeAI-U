package app

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp/builtin"
)

func TestLedgerToolRejectsInvalidWritesBeforeMutation(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	for _, tc := range []struct{ key, before, bad, diagnostic string }{
		{"recon/js/run-a/main", "assessment_id: run-a\nstatus: queued", "assessment_id: run-a\njs_resource: @package/ui\nstatus: expanded\nevidence: artifact:js", "js_resource"},
		{"recon/source/run-a/fofa/example", "assessment_id: run-a\ntool: fofa\ntarget: example.com\nstatus: gap", "assessment_id: run-a\ntool: fofa\ntarget: example.com\nstatus: covered\nraw: 112\nunique: 112\nincremental: 30+\nevidence: artifact:fofa", "incremental"},
		{"recon/assessment/run-a", "schema_version: 2\nmode: comprehensive\nassessment_id: run-a\nstatus: active\nscope_kind: single-url\nendpoint_count: 0\njs_count: 0\nrisk_unit_count: 0", "schema_version: 2\nmode: comprehensive\nassessment_id: run-a\nstatus: active\nscope_kind: single-url\nendpoint_count: 0\njs_count: 0\nrisk_unit_count: 0\nnotes: observation side_effects: none", "notes"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			original, err := db.UpsertProjectFact(&database.ProjectFact{ProjectID: projectID, FactKey: tc.key, Summary: "before", Body: tc.before, Confidence: "confirmed"})
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": tc.key, "summary": "invalid after", "body": tc.bad})
			if err != nil || result == nil || !result.IsError || !strings.Contains(toolResultText(result), tc.diagnostic) {
				t.Fatalf("bad ledger should produce field-level error: err=%v text=%s", err, toolResultText(result))
			}
			stored, err := db.GetProjectFactByKey(projectID, tc.key)
			if err != nil || stored.ID != original.ID || stored.Body != tc.before || stored.Summary != "before" {
				t.Fatalf("rejected write mutated existing fact: %v %+v", err, stored)
			}
		})
	}
	key := "recon/js/run-a/new-bad"
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": key, "summary": "bad", "body": "assessment_id: run-a\nresource: @bad"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("invalid create accepted: %v %+v", err, result)
	}
	if _, err := db.GetProjectFactByKey(projectID, key); err == nil {
		t.Fatal("invalid create reached DB")
	}
}

func TestStructuredLedgerBodyIsLosslessAndPatchSafe(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	_, err := db.UpsertProjectFact(&database.ProjectFact{ProjectID: projectID, FactKey: "target/root", Summary: "root", Body: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	key := "recon/js/run-a/main"
	fields := map[string]interface{}{"assessment_id": "run-a", "status": "expanded", "evidence": "artifact:main.js", "js_resource": "@package/ui", "notes": "side_effects: none"}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
		"fact_key": key, "summary": "JS expanded", "body_fields": fields, "confidence": "confirmed",
		"links": []interface{}{map[string]interface{}{"from": "target/root", "type": "supports"}},
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("structured write rejected: %v %s", err, toolResultText(result))
	}
	stored, err := db.GetProjectFactByKey(projectID, key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored.Body, "## 关联") {
		t.Fatal("expected host relationship mirror")
	}
	parsed, err := coverage.ParseLedgerBody(stored.Body)
	if err != nil || parsed["js_resource"] != fields["js_resource"] || parsed["notes"] != fields["notes"] {
		t.Fatalf("serialized values changed: %v %+v", err, parsed)
	}
	before := stored.Body
	result, _, err = server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": key, "summary": "summary only"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("summary-only patch rejected: %v %s", err, toolResultText(result))
	}
	stored, err = db.GetProjectFactByKey(projectID, key)
	if err != nil || stored.Body != before || stored.Confidence != "confirmed" {
		t.Fatalf("patch changed body/confidence: %v %+v", err, stored)
	}
	for _, args := range []map[string]interface{}{
		{"body": "text", "body_fields": fields},
		{"body_fields": "not an object"},
		{"body_fields": nil},
	} {
		args["fact_key"], args["summary"] = key, "invalid mixed input"
		result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("invalid structured arguments accepted: %v %+v", err, result)
		}
	}
}

func TestStructuredSourceCountDoesNotGuessApproximateText(t *testing.T) {
	_, server, ctx, _ := newProjectFactToolTest(t)
	fields := map[string]interface{}{"assessment_id": "run-a", "tool": "fofa", "target": "example.com", "status": "covered", "raw": 112, "unique": 112, "incremental": "30+", "evidence": "artifact:fofa"}
	args := map[string]interface{}{"fact_key": "recon/source/run-a/fofa/example", "summary": "inventory", "body_fields": fields}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
	if err != nil || result == nil || !result.IsError || !strings.Contains(toolResultText(result), "incremental") {
		t.Fatalf("approximate value guessed or accepted: %v %s", err, toolResultText(result))
	}
	fields["incremental"] = float64(30) // normal JSON integer argument representation
	result, _, err = server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("exact JSON integer rejected: %v %s", err, toolResultText(result))
	}
}

func TestCorruptLedgerCanBeDeprecatedButNotRestoredWithoutRepair(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	key := "recon/js/run-a/broken"
	_, err := db.UpsertProjectFact(&database.ProjectFact{ProjectID: projectID, FactKey: key, Summary: "old", Body: "resource: @bad", Confidence: "confirmed"})
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": key, "summary": "retired alias", "confidence": "deprecated"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("corrupt alias cannot be deprecated: %v %s", err, toolResultText(result))
	}
	result, _, err = server.CallTool(ctx, builtin.ToolRestoreProjectFact, map[string]interface{}{"fact_key": key})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("corrupt record restored without repair: %v %+v", err, result)
	}
}
