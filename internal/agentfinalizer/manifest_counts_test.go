package agentfinalizer

import (
	"encoding/json"
	"strings"
	"testing"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
)

func TestFinalizationDerivesLedgerCountsAcrossFactWrites(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "passed")
	in := Input{ConversationID: conversation, AssistantMessageID: message, Response: coverageReportFixture("已核对本轮证据及范围限制。"), RequireCoverageEvidence: true}
	key := "recon/js/run-a/main"
	save := func(status string) {
		t.Helper()
		_, err := db.UpsertProjectFact(&database.ProjectFact{
			ProjectID: project, SourceConversationID: conversation, FactKey: key,
			Category: "recon", Confidence: "confirmed", Summary: "JS resource",
			Body: "assessment_id: run-a\nstatus: " + status + "\nevidence: artifact:main.js",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// persistCoverage declared zero resources. Adding a closed resource must
	// not require a second model-written manifest update.
	save("expanded")
	d := Decide(db, in)
	if !d.Finalizable || d.CoverageLedgerCounts == nil || *d.CoverageLedgerCounts != (coverage.LedgerCounts{JSCount: 1}) {
		t.Fatalf("stale model count blocked delivery: %+v", d)
	}
	encoded, err := json.Marshal(d)
	if err != nil || !strings.Contains(string(encoded), `"coverageLedgerCounts":{"endpoint_count":0,"js_count":1,"risk_unit_count":0}`) {
		t.Fatalf("decision omitted authoritative counts: %v %s", err, encoded)
	}
	manifest, err := db.GetProjectFactByKey(project, "recon/assessment/run-a")
	if err != nil || !strings.Contains(manifest.Body, "js_count: 0") {
		t.Fatalf("checking rewrote persisted metadata: %v %+v", err, manifest)
	}
	// The derived count cannot turn an unfinished resource into coverage.
	save("queued")
	d = Decide(db, in)
	missing := strings.Join(d.MissingChecks, "\n")
	if d.Finalizable || !strings.Contains(missing, "not expanded") || strings.Contains(missing, "must equal inventory count") {
		t.Fatalf("derived count hid a genuine resource gap: %+v", d)
	}
}
