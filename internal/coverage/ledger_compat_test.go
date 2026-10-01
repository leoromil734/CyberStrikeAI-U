package coverage

import (
	"strings"
	"testing"
)

func TestLedgerParserAcceptsAssignmentHeaderAndIndentlessLists(t *testing.T) {
	body := "assessment_id=run-a; schema_version=2; mode=comprehensive; status=active; root_domain=example.com\nphases:\n- recon_sources: pending\n- frontend_api: pending\nnotes: 'literal; key=value; side_effects: none'"
	fields, err := ParseLedgerBody(body)
	if err != nil || text(fields, "assessment_id") != "run-a" || number(fields, "schema_version") != 2 {
		t.Fatalf("assignment header rejected or incorrectly typed: %v %+v", err, fields)
	}
	phases, ok := fields["phases"].([]any)
	if !ok || len(phases) != 2 || phases[0].(map[string]any)["recon_sources"] != "pending" {
		t.Fatalf("indentless YAML list flattened into root fields: %+v", fields)
	}
	if text(fields, "notes") != "literal; key=value; side_effects: none" {
		t.Fatalf("semicolon in ordinary field was split: %+v", fields)
	}
}

func TestLedgerParserPreservesYAMLIndentlessListsAndMarkdownFields(t *testing.T) {
	for _, body := range []string{
		"assessment_id: run-a\nphases:\n- recon_sources: pending\n- frontend_api: active",
		"```yaml\nassessment_id: run-a\nphases:\n- recon_sources: pending\n- frontend_api: active\n```",
		"- assessment_id: run-a\n- status: active\n- phases:\n  - recon_sources: pending\n  - frontend_api: active",
	} {
		fields, err := ParseLedgerBody(body)
		phases, ok := fields["phases"].([]any)
		if err != nil || text(fields, "assessment_id") != "run-a" || !ok || len(phases) != 2 {
			t.Fatalf("nested structure was not preserved: %q err=%v fields=%+v", body, err, fields)
		}
	}
}

func TestLedgerAssignmentHeaderRejectsAmbiguousOrDuplicateFields(t *testing.T) {
	for _, body := range []string{
		"assessment_id=run-a; assessment_id=run-b\nstatus: active",
		"assessment_id=run-a; schema_version=2\nassessment_id: run-b",
		"assessment_id=run-a; missing-assignment\nstatus: active",
		"assessment_id=run-a; notes='unterminated\nstatus: active",
		"assessment_id=run-a; notes={nested: value}\nstatus: active",
	} {
		if fields, err := ParseLedgerBody(body); err == nil {
			t.Fatalf("ambiguous header accepted: %q fields=%+v", body, fields)
		}
	}
	fields, err := ParseLedgerBody("assessment_id=run-a; notes='literal; notes=value'; schema_version=2\nstatus: active")
	if err != nil || text(fields, "notes") != "literal; notes=value" {
		t.Fatalf("quoted semicolon not preserved: %v %+v", err, fields)
	}
	if _, err := ParseLedgerBody("assessment_id=run-a\nnotes: observation side_effects: none"); err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "notes") {
		t.Fatalf("assignment compatibility hid ordinary YAML error: %v", err)
	}
}

func TestLedgerDraftManifestAllowsOnlyMissingStartupFields(t *testing.T) {
	key := "recon/assessment/run-a"
	body := "assessment_id: run-a\nschema_version: 2\nmode: comprehensive\nstatus: active"
	if err := ValidateLedgerFact(key, body); err != nil {
		t.Fatalf("startup manifest cannot be recorded: %v", err)
	}
	for _, suffix := range []string{"\nscope_kind: unknown", "\nendpoint_count: -1", "\njs_count: '0'", "\nrisk_unit_count: 30+"} {
		if err := ValidateLedgerFact(key, body+suffix); err == nil {
			t.Fatalf("explicit invalid startup field accepted: %s", suffix)
		}
	}
	if err := ValidateLedgerFact(key, strings.Replace(body, "status: active", "status: completed", 1)); err == nil {
		t.Fatal("incomplete manifest marked completed")
	}
}
