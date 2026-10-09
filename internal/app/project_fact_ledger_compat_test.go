package app

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/mcp/builtin"
)

func TestProjectFactToolRecoversNamespacedSourceObservation(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	key := "recon/source/run-20261001-goldseiten/subfinder/goldseiten.de"
	fields := map[string]interface{}{
		"alt_tried": "none", "error": "none", "fetched": 16, "incremental": 16,
		"key_findings": "datenbanksicherung.goldseiten.de (DB backup portal), piwik.goldseiten.de (Matomo), newsletter.goldseiten.de, mail.goldseiten.de, test3 series (2017/test environments), neu.newsletter",
		"raw":          "16 subdomains discovered", "status": "success", "target": "goldseiten.de",
		"time": "2026-10-01", "tool": "subfinder", "total": 16, "unique": 16,
	}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
		"fact_key": key, "summary": "subfinder goldseiten.de：16 子域。", "category": "recon",
		"confidence": "confirmed", "body_fields": fields,
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("reported source observation rejected: %v %s", err, toolResultText(result))
	}
	stored, err := db.GetProjectFactByKey(projectID, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := coverage.ParseLedgerBody(stored.Body)
	if err != nil || parsed["assessment_id"] != "run-20261001-goldseiten" || parsed["status"] != "active" ||
		parsed["source_status"] != "success" || parsed["raw_output"] != fields["raw"] || parsed["key_findings"] != fields["key_findings"] {
		t.Fatalf("observation was not preserved as an unfinished ledger: %v %+v", err, parsed)
	}
	if _, present := parsed["raw"]; present {
		t.Fatal("host guessed a raw count from prose/total/fetched")
	}
	if _, present := parsed["evidence"]; present {
		t.Fatal("host fabricated an execution evidence reference")
	}
	if fields["status"] != "success" || fields["raw"] != "16 subdomains discovered" {
		t.Fatal("normalization mutated caller arguments")
	}
	if text := toolResultText(result); !strings.Contains(text, "未完成") || !strings.Contains(text, "evidence") || !strings.Contains(text, "raw") {
		t.Fatalf("saved draft must explain its repair fields: %s", text)
	}

	// An explicit follow-up supplies actual counts and evidence; only then may
	// the source claim covered. No scan is performed by this test.
	fields["status"], fields["raw"], fields["evidence"] = "covered", 16, "execution:subfinder-original-result"
	result, _, err = server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
		"fact_key": key, "summary": "subfinder source with evidence", "body_fields": fields,
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("explicit evidenced repair rejected: %v %s", err, toolResultText(result))
	}
}

func TestProjectFactToolAcceptsAssignmentManifestAsDraft(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	key := "recon/assessment/run-20261001-live-db"
	body := "assessment_id=run-20261001-live-db; schema_version=2; mode=comprehensive; status=active; root_domain=live.deutsche-boerse.com\nphases:\n- recon_sources: pending（硬要求 fofa/subfinder/oneforall/dnsx，httpx 探活）\n- asset_ranking: pending\n- frontend_api: pending（JS 递归至队列空）\n- risk_matrix: pending（六类危害面：未授权敏感数据/默认口/越权/注入/RCE/上传）\n- auth_workflows: pending（计划复用 boerse-frankfurt A/B 账号 ROPC；6h 内有效）\n- gap_review: pending\nresource_budget: max_2_test_accounts_reuse_only; endpoint_ledger_target=all live platform hosts\nprior_dnr(boerse-frankfurt round): sso realm 开放重定向 negated；v1 POST 族匿名 401/403 强制；createWatchItem/deleteWatchItem 越权 negated；live-cat Basic 默认口 negated；kbc-frontend API 401。"
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
		"fact_key": key, "summary": "live platform assessment pending", "category": "recon", "body": body,
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("reported manifest rejected: %v %s", err, toolResultText(result))
	}
	stored, err := db.GetProjectFactByKey(projectID, key)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := coverage.ParseLedgerBody(stored.Body)
	if err != nil || fields["assessment_id"] != "run-20261001-live-db" || fields["schema_version"] != 2 || fields["root_domain"] != "live.deutsche-boerse.com" {
		t.Fatalf("assignment header changed: %v %+v", err, fields)
	}
	phases, ok := fields["phases"].([]interface{})
	if !ok || len(phases) != 6 || !strings.Contains(fields["resource_budget"].(string), "endpoint_ledger_target=all live platform hosts") {
		t.Fatalf("nested list or prose semicolon was changed: %+v", fields)
	}
	for _, name := range []string{"scope_kind", "endpoint_count", "js_count", "risk_unit_count"} {
		if _, present := fields[name]; present {
			t.Fatalf("draft invented missing %s", name)
		}
		if !strings.Contains(toolResultText(result), name) {
			t.Fatalf("draft did not explain missing %s: %s", name, toolResultText(result))
		}
	}
	report := coverage.Check([]coverage.Fact{{Key: key, Body: stored.Body}}, false)
	if !report.Active || report.AssessmentID != "run-20261001-live-db" || len(report.Missing) == 0 || report.ValidFacts != 0 {
		t.Fatalf("draft silently disabled/passed completion gate: %+v", report)
	}
	missing := strings.Join(report.Missing, "\n")
	if strings.Contains(missing, "_count") || report.LedgerCounts == nil || *report.LedgerCounts != (coverage.LedgerCounts{}) {
		t.Fatalf("host-owned empty counts created a completion gap: %+v", report)
	}
	for _, fragment := range []string{"scope_kind", "fofa_search", "recon/phase/run-20261001-live-db/recon_sources"} {
		if !strings.Contains(missing, fragment) {
			t.Fatalf("draft bypassed %s: %s", fragment, missing)
		}
	}
}

func TestProjectFactToolDoesNotRepairExplicitNamespaceConflicts(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	key := "recon/js/run-a/main"
	for _, id := range []interface{}{"run-b", "RUN-A", "", nil, 42} {
		result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
			"fact_key": key, "summary": "invalid explicit assessment", "body_fields": map[string]interface{}{"assessment_id": id, "status": "queued"},
		})
		if err != nil || result == nil || !result.IsError {
			t.Fatalf("explicit invalid/mismatched ID was overwritten: id=%v err=%v text=%s", id, err, toolResultText(result))
		}
		if _, err := db.GetProjectFactByKey(projectID, key); err == nil {
			t.Fatal("invalid explicit ID reached the database")
		}
	}
}

func TestProjectFactToolLedgerGuidanceMatchesWriteContract(t *testing.T) {
	_, server, _, _ := newProjectFactToolTest(t)
	for _, tool := range server.GetAllTools() {
		if tool.Name != builtin.ToolUpsertProjectFact {
			continue
		}
		for _, required := range []string{"body_fields", "assessment_id", "raw_output", "covered", "evidence", "scope_kind", "endpoint_count", "js_count", "risk_unit_count", "不能通过收尾门禁"} {
			if !strings.Contains(tool.Description, required) {
				t.Errorf("tool description omits %q", required)
			}
		}
		properties := tool.InputSchema["properties"].(map[string]interface{})
		keyDescription := properties["fact_key"].(map[string]interface{})["description"].(string)
		if !strings.Contains(keyDescription, "recon/source/{id}/{tool}/{target_id}") {
			t.Fatalf("tool still recommends an unversioned source key: %s", keyDescription)
		}
		return
	}
	t.Fatal("project fact tool not registered")
}

func TestProjectFactToolInfersNamespaceBeforeCanonicalEndpoint(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	key := "recon/endpoint/run-a/guess"
	fields := map[string]interface{}{"endpoint_url": "https://api.example.com:8443/A/b", "method": "GET", "runtime_status": "discovered"}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": key, "summary": "discovered endpoint", "body_fields": fields})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("namespace inference happened too late: %v %s", err, toolResultText(result))
	}
	slug, err := coverage.EndpointKey(fields["endpoint_url"].(string), "GET")
	if err != nil {
		t.Fatal(err)
	}
	canonical := "recon/endpoint/run-a/" + slug
	if _, err := db.GetProjectFactByKey(projectID, canonical); err != nil {
		t.Fatalf("canonical endpoint not saved: %v", err)
	}
	if _, err := db.GetProjectFactByKey(projectID, key); err == nil {
		t.Fatal("unsafe alias saved alongside canonical endpoint")
	}
}
