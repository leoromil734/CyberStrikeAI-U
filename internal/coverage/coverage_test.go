package coverage

import (
	"fmt"
	"strings"
	"testing"
)

func validLedger(scope string) []Fact {
	facts := []Fact{{"recon/assessment/run-a", "schema_version: 2\nmode: comprehensive\nassessment_id: run-a\nstatus: active\nendpoint_count: 1\njs_count: 1\nrisk_unit_count: 1\nscope_kind: " + scope}}
	for _, phase := range phases {
		facts = append(facts, Fact{"recon/phase/run-a/" + phase, "assessment_id: run-a\nstatus: passed\nevidence: execution:baseline"})
	}
	for _, tool := range []string{"subfinder", "oneforall", "dnsx"} {
		facts = append(facts, Fact{"recon/source/" + tool + "/example", "assessment_id: run-a\nstatus: covered\ntool: " + tool + "\ntarget: example.com\nraw: 2\nunique: 2\nincremental: 1\nevidence: execution:source"})
	}
	facts = append(facts,
		Fact{"recon/js/run-a/main", "assessment_id: run-a\nstatus: expanded\nevidence: artifact:main.js"},
		Fact{"recon/endpoint/run-a/users", "assessment_id: run-a\nhost: api.example.com\nmethod: GET\npath: /users\nruntime_status: risk-mapped\nevidence: execution:baseline\nrisk_units: [recon/risk/run-a/auth-a]"},
		Fact{"recon/risk/run-a/auth-a", "assessment_id: run-a\nendpoint_key: recon/endpoint/run-a/users\nrisk_family: object-authorization\nidentity: account-a\nstatus: negated\nevidence: execution:comparison"},
	)
	return facts
}

func TestCheckDoesNotInferIntentFromLegacyNotes(t *testing.T) {
	r := Check([]Fact{{"recon/phase/risk_matrix", "status: pending\nevidence: not-yet"}}, false)
	if r.Active || len(r.Missing) != 0 {
		t.Fatalf("ordinary/legacy note must not activate gate: %+v", r)
	}
	if r = Check(nil, true); !r.Active || len(r.Missing) == 0 {
		t.Fatalf("explicit requirement must fail closed without manifest: %+v", r)
	}
}

func TestCheckValidAssessment(t *testing.T) {
	for _, scope := range []string{"root-domain", "single-url", "ip", "asset-list"} {
		t.Run(scope, func(t *testing.T) {
			r := Check(validLedger(scope), false)
			if !r.Active || r.AssessmentID != "run-a" || len(r.Missing) != 0 || len(r.EvidenceRefs) == 0 {
				t.Fatalf("valid ledger rejected: %+v", r)
			}
		})
	}
}

func TestCheckDetectsExecutableGapsAndInvalidEvidence(t *testing.T) {
	cases := []struct{ name, key, old, replacement, want string }{
		{"phase pending", "recon/phase/run-a/risk_matrix", "status: passed", "status: pending", "phase needs terminal"},
		{"JS queue", "recon/js/run-a/main", "status: expanded", "status: analyzed", "not expanded"},
		{"unmapped endpoint", "recon/endpoint/run-a/users", "runtime_status: risk-mapped", "runtime_status: extracted", "needs baseline"},
		{"missing unit", "recon/endpoint/run-a/users", "risk_units: [recon/risk/run-a/auth-a]", "risk_units: []", "missing applicable risk_units"},
		{"tentative risk", "recon/risk/run-a/auth-a", "status: negated", "status: tentative", "risk unit needs terminal"},
		{"unproven N/A", "recon/risk/run-a/auth-a", "status: negated", "status: not-applicable", "requires a concrete reason"},
		{"placeholder", "recon/risk/run-a/auth-a", "evidence: execution:comparison", "evidence: '<evidence>'", "risk unit needs terminal"},
		{"negative source counts", "recon/source/subfinder/example", "raw: 2", "raw: -2", "valid counts"},
		{"wrong count type", "recon/source/subfinder/example", "unique: 2", "unique: '2'", "valid counts"},
		{"blocked no alternatives", "recon/source/oneforall/example", "status: covered", "status: blocked\nerror: connection failed", "blocker/alternative"},
		{"risk wrong endpoint", "recon/risk/run-a/auth-a", "endpoint_key: recon/endpoint/run-a/users", "endpoint_key: recon/endpoint/run-b/users", "referenced endpoint is absent"},
		{"wrong assessment", "recon/risk/run-a/auth-a", "assessment_id: run-a", "assessment_id: run-b", "missing or mismatched risk"},
		{"manifest key mismatch", "recon/assessment/run-a", "assessment_id: run-a", "assessment_id: another", "key must match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := validLedger("root-domain")
			for i := range facts {
				if facts[i].Key == tc.key {
					facts[i].Body = strings.Replace(facts[i].Body, tc.old, tc.replacement, 1)
				}
			}
			r := Check(facts, true)
			if !strings.Contains(strings.Join(r.Missing, "\n"), tc.want) {
				t.Fatalf("missing %q in %+v", tc.want, r)
			}
		})
	}
}

func TestCheckBlockedAndExcludedUnitsAreTerminal(t *testing.T) {
	for _, status := range []string{"blocked", "not-applicable"} {
		facts := validLedger("root-domain")
		facts[len(facts)-1].Body = strings.Replace(facts[len(facts)-1].Body, "status: negated", "status: "+status+"\nreason: policy exclusion or unavailable approved identity", 1)
		if r := Check(facts, true); len(r.Missing) != 0 {
			t.Fatalf("evidenced %s should be terminal: %+v", status, r)
		}
	}
}

func TestCheckRootSourceRequirementsAreScopeDependent(t *testing.T) {
	facts := validLedger("root-domain")
	var filtered []Fact
	for _, f := range facts {
		if !strings.Contains(f.Key, "/oneforall/") {
			filtered = append(filtered, f)
		}
	}
	if r := Check(filtered, true); !strings.Contains(strings.Join(r.Missing, "\n"), "oneforall") {
		t.Fatalf("missing root source unnoticed: %+v", r)
	}
	filtered[0].Body = strings.Replace(filtered[0].Body, "root-domain", "single-url", 1)
	if r := Check(filtered, true); len(r.Missing) != 0 {
		t.Fatalf("single URL should not require root enumeration: %+v", r)
	}
}

func TestCheckRejectsMalformedAndDuplicateLedger(t *testing.T) {
	facts := validLedger("single-url")
	facts = append(facts, Fact{"recon/js/run-a/broken", "assessment_id: ["})
	if r := Check(facts, true); !strings.Contains(strings.Join(r.Missing, "\n"), "invalid ledger body") {
		t.Fatalf("malformed resource hidden: %+v", r)
	}
	facts = validLedger("single-url")
	facts = append(facts, facts[0])
	if r := Check(facts, true); !strings.Contains(strings.Join(r.Missing, "\n"), "multiple active") {
		t.Fatalf("ambiguous assessment accepted: %+v", r)
	}
}

func TestParseBodyUsesActualFieldsNotKeywordPresence(t *testing.T) {
	for _, body := range []string{"```yaml\nstatus: passed\nevidence: execution:1\n```", "- status: passed\n- evidence: execution:1", `{"status":"passed","evidence":"execution:1"}`} {
		f, err := parseBody(body)
		if err != nil || text(f, "status") != "passed" {
			t.Fatalf("parse %q: %v %+v", body, err, f)
		}
	}
	f, err := parseBody("notes: status evidence passed")
	if err != nil || text(f, "status") != "" {
		t.Fatalf("keywords must not become fields: %v %+v", err, f)
	}
}

func TestEndpointKeyPreservesOriginAndPathBoundaries(t *testing.T) {
	seen := map[string]string{}
	for _, target := range []string{"https://example.com/a/b", "https://example.com/a-b", "https://example.com/A/b", "https://example.com:8443/a/b", "http://example.com/a/b", "https://example.com/" + strings.Repeat("x", 200) + "a", "https://example.com/" + strings.Repeat("x", 200) + "b"} {
		key, err := EndpointKey(target, "GET")
		if err != nil {
			t.Fatal(err)
		}
		if previous := seen[key]; previous != "" {
			t.Fatalf("collision: %s and %s", target, previous)
		}
		seen[key] = target
	}
	a, _ := EndpointKey("https://EXAMPLE.com/a/b?object=1#fragment", "get")
	b, _ := EndpointKey("https://example.com:443/a/b?object=2", "GET")
	if a != b {
		t.Fatalf("equivalent endpoint origins should normalize: %s != %s", a, b)
	}
	for _, target := range []string{"file:///tmp/test", "https://user:pass@example.com", "/relative"} {
		if _, err := EndpointKey(target, "GET"); err == nil {
			t.Fatal(fmt.Sprintf("invalid endpoint accepted: %s", target))
		}
	}
}
