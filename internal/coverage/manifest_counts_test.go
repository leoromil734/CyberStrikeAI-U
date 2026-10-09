package coverage

import (
	"reflect"
	"strings"
	"testing"
)

func TestManifestCountsAreDerivedWithoutModelSynchronization(t *testing.T) {
	for _, declaration := range []string{
		"", // New manifests omit host-owned metadata, including when completed.
		"endpoint_count: 0\njs_count: 999\nrisk_unit_count: 8\n",
		"endpoint_count: 999\njs_count: 0\nrisk_unit_count: 0\n",
	} {
		for _, status := range []string{"active", "completed"} {
			facts := validLedger("single-url")
			facts[0].Body = "schema_version: 2\nmode: comprehensive\nassessment_id: run-a\nstatus: " + status + "\nscope_kind: single-url\n" + declaration
			if err := ValidateLedgerFact(facts[0].Key, facts[0].Body); err != nil {
				t.Fatalf("optional/legacy count write rejected: %v", err)
			}
			before := append([]Fact(nil), facts...)
			r := Check(facts, true)
			want := LedgerCounts{EndpointCount: 1, JSCount: 1, RiskUnitCount: 1}
			if len(r.Missing) != 0 || r.LedgerCounts == nil || *r.LedgerCounts != want {
				t.Fatalf("host counts depended on declaration %q: %+v", declaration, r)
			}
			if !reflect.DeepEqual(facts, before) {
				t.Fatal("checking mutated the caller's facts")
			}

			// A later write is visible without any manifest write. Counts are not
			// cached, so removing that fact also yields the current snapshot.
			facts = append(facts, Fact{"recon/js/run-a/later", "assessment_id: run-a\nstatus: expanded\nevidence: artifact:later.js"})
			grown := Check(facts, true)
			if len(grown.Missing) != 0 || grown.LedgerCounts.JSCount != 2 || r.LedgerCounts.JSCount != 1 {
				t.Fatalf("count snapshot was stale or shared: %+v", grown)
			}
			shrunk := Check(facts[:len(facts)-1], true)
			if len(shrunk.Missing) != 0 || *shrunk.LedgerCounts != want {
				t.Fatalf("count did not follow deletion: %+v", shrunk)
			}
		}
	}
}

func TestDerivedManifestCountsKeepMalformedAndDuplicateFactsVisible(t *testing.T) {
	facts := validLedger("single-url")
	facts = append(facts,
		Fact{"recon/js/run-a/broken", "assessment_id: ["},
		Fact{"recon/js/run-a/wrong-id", "assessment_id: run-b\nstatus: expanded\nevidence: artifact:wrong"},
		Fact{"recon/js/run-b/other", "assessment_id: run-b\nstatus: expanded\nevidence: artifact:other"},
		Fact{"recon/js/legacy", "assessment_id: run-a\nstatus: expanded\nevidence: artifact:legacy"},
		Fact{"recon/js/unbound", "status: expanded\nevidence: artifact:unbound"},
		Fact{"recon/note/run-a/free", "not: [valid"},
	)
	facts = append(facts, facts[len(facts)-3]) // duplicate legacy key counts once but remains a gap
	r := Check(facts, true)
	if r.LedgerCounts == nil || *r.LedgerCounts != (LedgerCounts{EndpointCount: 1, JSCount: 4, RiskUnitCount: 1}) {
		t.Fatalf("host count lost namespace/unique-key boundaries: %+v", r)
	}
	missing := strings.Join(r.Missing, "\n")
	for _, want := range []string{"broken: invalid ledger body", "wrong-id: assessment_id does not match", "legacy: duplicate ledger key"} {
		if !strings.Contains(missing, want) {
			t.Fatalf("derived counts hid %q: %s", want, missing)
		}
	}
	if strings.Contains(missing, "must equal inventory count") {
		t.Fatalf("model was asked to repair host counts: %s", missing)
	}
}

func TestDerivedManifestCountsNeverInventRiskMapping(t *testing.T) {
	facts := validLedger("single-url")
	facts[0].Body = "schema_version: 2\nmode: comprehensive\nassessment_id: run-a\nstatus: completed\nscope_kind: single-url"
	for i := range facts {
		if facts[i].Key == "recon/endpoint/run-a/users" {
			facts[i].Body = strings.Replace(facts[i].Body, "risk_units: [recon/risk/run-a/auth-a]", "risk_units: []", 1)
		}
	}
	r := Check(facts, true)
	if r.LedgerCounts == nil || r.LedgerCounts.RiskUnitCount != 1 || !strings.Contains(strings.Join(r.Missing, "\n"), "missing applicable risk_units") {
		t.Fatalf("count derivation invented risk mapping or concealed a gap: %+v", r)
	}
}
