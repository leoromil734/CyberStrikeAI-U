package agentfinalizer

import (
	"context"
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"strings"
	"testing"
	"time"
)

func TestGovernedCoverageCannotUseInventedSourceExecution(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "passed")
	_, err := db.BeginAssessmentRun(conversation, project, "", "", database.AssessmentModeComprehensive, "run-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = db.SaveToolExecution(&mcp.ToolExecution{ID: "baseline", ToolName: "httpx", ConversationID: conversation, Status: "completed", StartTime: now, EndTime: &now}); err != nil {
		t.Fatal(err)
	}
	d := Decide(db, Input{ConversationID: conversation, AssistantMessageID: message, Response: "本轮评估报告已经整理完成。", MCPExecutionIDs: []string{"baseline"}})
	if d.Finalizable || !strings.Contains(strings.Join(d.MissingChecks, "\n"), "actual execution/original") {
		t.Fatalf("fictional sources finalized: %+v", d)
	}
}
func TestIndependentOriginalIngestionBlocksFinalizationWhilePending(t *testing.T) {
	db, project, conversation, _ := coverageTestDB(t)
	e := evidence.Execution{ID: "pending-ingestion", Access: evidence.Access{ProjectID: project, ConversationID: conversation, Owner: "owner"}, ScopeID: "scope", AssessmentID: "run-a", Tool: "gau", Status: "completed", Completion: evidence.Complete}
	ctx := evidence.WithAccess(context.Background(), e.Access)
	if err := db.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := db.SetResultIngestionState(ctx, e, "pending", ""); err != nil {
		t.Fatal(err)
	}
	r := coverage.Report{Active: true}
	checkIndependentInventory(db, project, conversation, "run-a", nil, &r)
	if !strings.Contains(strings.Join(r.Missing, "\n"), "still pending") {
		t.Fatal(r)
	}
}
func TestGovernedReportMustReferencePersistedFormalFindingIDs(t *testing.T) {
	db, project, conversation, _ := coverageTestDB(t)
	_, err := db.BeginAssessmentRun(conversation, project, "", "", database.AssessmentModeComprehensive, "run-report")
	if err != nil {
		t.Fatal(err)
	}
	v, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: conversation, ProjectID: project, Title: "fixture", Severity: "high", Status: "open", Type: "fixture", Target: "https://example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	in := Input{ConversationID: conversation, Response: "本轮已确认漏洞: 1。"}
	if checks := reportFindingChecks(db, in); len(checks) == 0 {
		t.Fatal("unlinked report accepted")
	}
	in.Response = "本轮已确认漏洞: 1。finding: " + v.ID
	if checks := reportFindingChecks(db, in); len(checks) != 0 {
		t.Fatal(checks)
	}
	in.Response = "本轮已确认漏洞: 2。finding: " + v.ID
	if checks := reportFindingChecks(db, in); len(checks) == 0 {
		t.Fatal("candidate count promoted")
	}
}
func TestRefusalEndsBeforeIncompleteCandidateContinuation(t *testing.T) {
	d := Decide(nil, Input{Response: "I cannot perform penetration testing on this target", RequireExecutionEvidence: true})
	if !d.Finalizable || d.Status != StatusDeclined || d.EvidenceVerified {
		t.Fatal(d)
	}
	if IsExplicitRefusal("> I cannot perform penetration testing on this target") {
		t.Fatal("quoted evidence classified as own refusal")
	}
}
