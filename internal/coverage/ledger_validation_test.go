package coverage

import (
	"strings"
	"testing"
)

func TestMalformedJSStillCountsInStoredInventory(t *testing.T) {
	facts := validLedger("single-url")
	facts[0].Body = strings.Replace(facts[0].Body, "js_count: 1", "js_count: 4", 1)
	for _, id := range []string{"two", "three"} {
		facts = append(facts, Fact{"recon/js/run-a/" + id, "assessment_id: run-a\nstatus: expanded\nevidence: artifact:" + id})
	}
	facts = append(facts, Fact{"recon/js/run-a/components", "assessment_id: run-a\njs_resource: @finanztip/ft-ui-* 组件族\nstatus: expanded\nevidence: artifact:components"})
	r := Check(facts, true)
	missing := strings.Join(r.Missing, "\n")
	if !strings.Contains(missing, "recon/js/run-a/components: invalid ledger body") || !strings.Contains(missing, "js_resource") {
		t.Fatalf("exact bad field not reported: %+v", r)
	}
	if strings.Contains(missing, "js_count must equal") {
		t.Fatalf("a parse error must not reduce stored inventory: %s", missing)
	}
	facts[len(facts)-1].Body = strings.Replace(facts[len(facts)-1].Body, "@finanztip/ft-ui-* 组件族", "'@finanztip/ft-ui-* 组件族'", 1)
	fixed := Check(facts, true)
	if len(fixed.Missing) != 0 || fixed.ValidFacts <= r.ValidFacts {
		t.Fatalf("quoted repair should retain 4 resources and increase progress: before=%+v after=%+v", r, fixed)
	}
}

func TestCoverageApproximateSourceCountHasSpecificDiagnostic(t *testing.T) {
	facts := validLedger("root-domain")
	facts = append(facts, Fact{"recon/source/run-a/fofa/example.com", "assessment_id: run-a\ntool: fofa\ntarget: example.com\nstatus: covered\nraw: 112\nunique: 112\nincremental: 30+\nevidence: artifact:fofa-result"})
	r := Check(facts, true)
	if !strings.Contains(strings.Join(r.Missing, "\n"), "incremental must be a non-negative integer") {
		t.Fatalf("approximate text count was not diagnosed: %+v", r)
	}
}

func TestCoverageManifestErrorRetainsSyntaxAndIgnoresFreeNotes(t *testing.T) {
	facts := validLedger("single-url")
	facts = append(facts, Fact{"recon/note/run-a/free", "free form:\nwith side_effects: observations [broken"}, Fact{"recon/asset/run-a/free", "raw @ observations"})
	if r := Check(facts, true); len(r.Missing) != 0 {
		t.Fatalf("free notes/assets must not enter the ledger gate: %+v", r)
	}
	facts[0].Body += "\nnotes: long observation includes side_effects: none"
	r := Check(facts, true)
	missing := strings.Join(r.Missing, "\n")
	if !strings.Contains(missing, "invalid comprehensive manifest") || !strings.Contains(missing, "line") || !strings.Contains(missing, "notes") || r.ValidFacts != 0 {
		t.Fatalf("broken manifest must fail closed with exact syntax detail: %+v", r)
	}
}

func TestLedgerParserPreservesNestedListsAndJSONRelationshipMirror(t *testing.T) {
	fields, err := ParseLedgerBody("assessment_id: run-a\nrisk_units:\n  - recon/risk/run-a/one\n  - recon/risk/run-a/two\nalt_tried:\n  - tool: dnsx\n    result: timeout")
	if err != nil || len(list(fields, "risk_units")) != 2 {
		t.Fatalf("nested YAML lists were changed: %v %+v", err, fields)
	}
	body := `{"assessment_id":"run-a","status":"expanded","evidence":"artifact:js","js_resource":"@package/ui","notes":"side_effects: none"}` + "\n\n## 关联\n- 关系边（结构化同步）:\n  - supports: target/root"
	fields, err = ParseLedgerBody(body)
	if err != nil || text(fields, "js_resource") != "@package/ui" || text(fields, "notes") != "side_effects: none" {
		t.Fatalf("host relationship mirror must not corrupt JSON: %v %+v", err, fields)
	}
	if err := ValidateLedgerFact("recon/js/run-a/main", body); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLedgerBody(`{"status":"expanded"} unexpected`); err == nil {
		t.Fatal("unrecognized trailing text was silently discarded")
	}
}

func TestLedgerWriteContractAllowsIntermediateStatesAndRequiresTerminalEvidence(t *testing.T) {
	for _, f := range []Fact{
		{"recon/js/run-a/main", "assessment_id: run-a\nstatus: queued"},
		{"recon/phase/run-a/frontend_api", "assessment_id: run-a\nstatus: active"},
		{"recon/source/run-a/fofa/example", "assessment_id: run-a\nstatus: gap\ntool: fofa\ntarget: example.com"},
		{"recon/endpoint/run-a/main", "assessment_id: run-a\nruntime_status: discovered"},
		{"recon/risk/run-a/one", "assessment_id: run-a\nstatus: waiting\nendpoint_key: recon/endpoint/run-a/main\nrisk_family: auth\nidentity: anonymous"},
		{"recon/source/fofa/example", "legacy free text @"},
		{"recon/note/run-a/one", "unstructured side_effects: value: true"},
	} {
		if err := ValidateLedgerFact(f.Key, f.Body); err != nil {
			t.Fatalf("legitimate intermediate/legacy write rejected: %s: %v", f.Key, err)
		}
	}
	for _, f := range []Fact{
		{"recon/js/run-a/main", "assessment_id: run-a\nstatus: expanded"},
		{"recon/phase/run-a/frontend_api", "assessment_id: run-a\nstatus: passed"},
		{"recon/endpoint/run-a/main", "assessment_id: run-a\nruntime_status: verified"},
		{"recon/js/run-a/main", "assessment_id: run-b\nstatus: queued"},
	} {
		if err := ValidateLedgerFact(f.Key, f.Body); err == nil {
			t.Fatalf("invalid terminal/namespace write accepted: %+v", f)
		}
	}
}
