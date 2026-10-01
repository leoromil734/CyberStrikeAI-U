package coverage

import (
	"strings"
	"testing"
)

func withoutFOFA(facts []Fact) []Fact {
	var out []Fact
	for _, fact := range facts {
		if !strings.Contains(fact.Key, "/fofa_search/") {
			out = append(out, fact)
		}
	}
	return out
}

func TestInitialFOFASourceRequiredForEveryComprehensiveScope(t *testing.T) {
	for _, scope := range []string{"root-domain", "single-url", "ip", "asset-list"} {
		t.Run(scope, func(t *testing.T) {
			facts := withoutFOFA(validLedger(scope))
			// Other space engines are supplemental, not substitutes for FOFA.
			facts = append(facts, Fact{"recon/source/run-a/shodan_search/example", "assessment_id: run-a\ntool: shodan_search\ntarget: example.com\nstatus: covered\nraw: 0\nunique: 0\nincremental: 0\nevidence: execution:shodan"})
			r := Check(facts, true)
			if !strings.Contains(strings.Join(r.Missing, "\n"), "recon/source for fofa_search") {
				t.Fatalf("FOFA absent but assessment passed: %+v", r)
			}
		})
	}
}

func TestInitialFOFAAcceptsActualZeroResultsAndEvidencedBlockers(t *testing.T) {
	for _, status := range []string{"covered", "blocked"} {
		t.Run(status, func(t *testing.T) {
			facts := withoutFOFA(validLedger("single-url"))
			body := "assessment_id: run-a\ntool: fofa_search\ntarget: https://example.com\nraw: 0\nunique: 0\nincremental: 0\nstatus: " + status + "\nevidence: execution:fofa-original-result"
			if status == "blocked" {
				body += "\nerror: missing configured FOFA key\nalt_tried: [certificate-transparency]"
			}
			facts = append(facts, Fact{"recon/source/run-a/fofa_search/example", body})
			if r := Check(facts, true); len(r.Missing) != 0 {
				t.Fatalf("valid FOFA outcome rejected: %+v", r)
			}
		})
	}
}

func TestInitialFOFARejectsUnexecutedExemptAndStaleSources(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
	}{
		{"unexecuted", "assessment_id: run-a\nstatus: gap"},
		{"N/A is not an escape", "assessment_id: run-a\nstatus: not-applicable\nreason: fixed URL so skip search"},
		{"blocker without alternatives", "assessment_id: run-a\nstatus: blocked\nerror: no configured key"},
		{"old assessment", "assessment_id: run-old\nstatus: covered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := withoutFOFA(validLedger("single-url"))
			body := tc.fields + "\ntool: fofa_search\ntarget: example.com\nraw: 0\nunique: 0\nincremental: 0\nevidence: execution:fofa"
			facts = append(facts, Fact{"recon/source/fofa_search/example", body})
			if r := Check(facts, true); !strings.Contains(strings.Join(r.Missing, "\n"), "recon/source for fofa_search") {
				t.Fatalf("invalid FOFA source satisfied mandatory requirement: %+v", r)
			}
		})
	}
}

func TestFOFARequirementDoesNotActivateOnOrdinaryNotes(t *testing.T) {
	r := Check([]Fact{{"recon/note/fofa", "FOFA query has not been run"}}, false)
	if r.Active || len(r.Missing) != 0 {
		t.Fatalf("ordinary note activated comprehensive gate: %+v", r)
	}
}
