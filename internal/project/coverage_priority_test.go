package project

import (
	"cyberstrike-ai/internal/database"
	"testing"
)

func TestFactIndexKeepsOpenCoverageAheadOfCompletedFindings(t *testing.T) {
	finding := &database.ProjectFact{FactKey: "finding/old", Category: "finding", Confidence: "confirmed"}
	for _, fact := range []*database.ProjectFact{
		{FactKey: "recon/assessment/run-a", Category: "recon", Body: "status: active"},
		{FactKey: "recon/phase/run-a/risk_matrix", Category: "recon", Body: "status: pending"},
		{FactKey: "recon/js/run-a/main", Category: "recon", Body: "status: analyzed"},
		{FactKey: "recon/risk/run-a/auth", Category: "recon", Body: "status: waiting"},
		{FactKey: "recon/endpoint/run-a/users", Category: "recon", Body: "runtime_status: extracted"},
	} {
		if factIndexSortPriority(fact) <= factIndexSortPriority(finding) {
			t.Fatalf("open work lost behind findings: %s", fact.FactKey)
		}
	}
	pinned := &database.ProjectFact{FactKey: "target/current", Category: "target", Pinned: true}
	active := &database.ProjectFact{FactKey: "recon/phase/run-a/risk_matrix", Category: "recon", Body: "status: active"}
	if factIndexSortPriority(pinned) <= factIndexSortPriority(active) {
		t.Fatal("explicit user pin must retain priority")
	}
	completed := &database.ProjectFact{FactKey: "recon/phase/run-a/risk_matrix", Category: "recon", Body: "status: passed\nevidence: done"}
	if factIndexSortPriority(completed) >= factIndexSortPriority(finding) {
		t.Fatal("completed phase should not crowd out findings")
	}
}
