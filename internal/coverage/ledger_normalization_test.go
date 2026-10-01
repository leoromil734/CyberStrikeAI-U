package coverage

import (
	"strings"
	"testing"
)

func TestNormalizedSourceSuccessCannotPassCoverage(t *testing.T) {
	for _, tool := range []string{"fofa_search", "subfinder"} {
		facts := validLedger("root-domain")
		key := "recon/source/run-a/" + tool + "/example.com"
		body, notes, err := NormalizeLedgerWrite(key, "tool: "+tool+"\ntarget: example.com\nstatus: success\nraw: 2\nunique: 2\nincremental: 1\nevidence: execution:source")
		if err != nil || len(notes) == 0 {
			t.Fatalf("success normalization failed: %v %+v", err, notes)
		}
		if err := ValidateLedgerFact(key, body); err != nil {
			t.Fatalf("normalized intermediate rejected: %v", err)
		}
		for i, fact := range facts {
			if fact.Key == "recon/source/"+tool+"/example" {
				facts[i] = Fact{key, body}
			}
		}
		r := Check(facts, true)
		if !r.Active || !strings.Contains(strings.Join(r.Missing, "\n"), "recon/source for "+tool) {
			t.Fatalf("tool success silently became completed source coverage: tool=%s report=%+v", tool, r)
		}
		// Completion must be explicit, with the already supplied exact counts
		// and evidence. Namespace metadata alone is safe to synchronize.
		body = strings.Replace(body, `"status":"active"`, `"status":"covered"`, 1)
		for i, fact := range facts {
			if fact.Key == key {
				facts[i].Body = body
			}
		}
		if r := Check(facts, true); len(r.Missing) != 0 {
			t.Fatalf("evidenced explicit terminal repair rejected: %+v", r)
		}
	}
}

func TestLedgerNormalizationPreservesLegacyAndRejectsConflictingTransportFields(t *testing.T) {
	for _, f := range []Fact{
		{"recon/note/run-a/one", "text @ with side_effects: none"},
		{"recon/source/subfinder/example.com", "legacy @ observations"},
		{"recon/source/subfinder/example.com", "tool: subfinder\nstatus: success\nraw: '16 results'"},
	} {
		body, notes, err := NormalizeLedgerWrite(f.Key, f.Body)
		if err != nil || body != f.Body || len(notes) != 0 {
			t.Fatalf("legacy note changed or promoted: %+v body=%q err=%v notes=%+v", f, body, err, notes)
		}
	}
	for _, extra := range []string{"\nraw_output: different output", "\nsource_status: failed"} {
		if _, _, err := NormalizeLedgerWrite("recon/source/run-a/subfinder/example", "tool: subfinder\ntarget: example.com\nstatus: success\nraw: '16 results'"+extra); err == nil {
			t.Fatalf("transport compatibility overwrote conflicting user field: %s", extra)
		}
	}
}

func TestNormalizedJSONLedgerRetainsRelationshipMirror(t *testing.T) {
	mirror := "\n\n## 关联\n- 关系边（结构化同步）:\n  - supports: target/root"
	body, _, err := NormalizeLedgerWrite("recon/js/run-a/main", `{"status":"queued","js_resource":"@package/ui"}`+mirror)
	if err != nil || !strings.HasSuffix(body, mirror) {
		t.Fatalf("normalization lost the host relationship mirror: err=%v body=%s", err, body)
	}
	fields, err := ParseLedgerBody(body)
	if err != nil || text(fields, "assessment_id") != "run-a" || text(fields, "js_resource") != "@package/ui" {
		t.Fatalf("mirrored normalized object cannot be parsed: %v %+v", err, fields)
	}
}

func TestNormalizedTerminalSourceStillRequiresExactCountsAndEvidence(t *testing.T) {
	for _, suffix := range []string{
		"raw: '16 subdomains discovered'\nunique: 16\nincremental: 16\nevidence: execution:source",
		"raw: 16\nunique: 16\nincremental: 30+\nevidence: execution:source",
		"raw: 16\nunique: 16\nincremental: 16",
	} {
		key := "recon/source/run-a/subfinder/example.com"
		body, _, err := NormalizeLedgerWrite(key, "tool: subfinder\ntarget: example.com\nstatus: covered\n"+suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateLedgerFact(key, body); err == nil {
			t.Fatalf("terminal source bypassed exact-count/evidence gate: %s", body)
		}
	}
}
