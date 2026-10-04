package agentfinalizer

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func coverageTestDB(t *testing.T) (*database.DB, string, string, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "coverage.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	project, err := db.CreateProject(&database.Project{Name: "coverage"})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("coverage", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(conv.ID, project.ID); err != nil {
		t.Fatal(err)
	}
	message, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, project.ID, conv.ID, message.ID
}

func persistCoverage(t *testing.T, db *database.DB, project, conversation, phaseStatus string) {
	t.Helper()
	body := "schema_version: 2\nassessment_id: run-a\nmode: comprehensive\nstatus: active\nscope_kind: single-url\nendpoint_count: 0\njs_count: 0\nrisk_unit_count: 0"
	facts := []database.ProjectFact{{FactKey: "recon/assessment/run-a", Body: body}, {FactKey: "recon/source/httpx/run-a", Body: "assessment_id: run-a\ntool: httpx\ntarget: https://example.com\nstatus: covered\nraw: 1\nunique: 1\nincremental: 1\nevidence: execution:baseline"}, {FactKey: "recon/source/run-a/fofa_search/example", Body: "assessment_id: run-a\ntool: fofa_search\ntarget: https://example.com\nstatus: covered\nraw: 0\nunique: 0\nincremental: 0\nevidence: execution:fofa-empty-result"}}
	for _, phase := range []string{"recon_sources", "asset_ranking", "frontend_api", "auth_workflows", "risk_matrix", "gap_review"} {
		status := "passed"
		if phase == "risk_matrix" {
			status = phaseStatus
		}
		facts = append(facts, database.ProjectFact{FactKey: "recon/phase/run-a/" + phase, Body: fmt.Sprintf("assessment_id: run-a\nstatus: %s\nevidence: execution:baseline", status)})
	}
	for _, fact := range facts {
		fact.ProjectID, fact.SourceConversationID = project, conversation
		fact.Category, fact.Confidence, fact.Summary = "recon", "confirmed", "coverage ledger"
		if _, err := db.UpsertProjectFact(&fact); err != nil {
			t.Fatal(err)
		}
	}
}

func coverageReportFixture(summary string) string {
	return "# 评估报告\n\n## 风险概览与测试范围\n" + summary + "\n\n## 已保存证据与范围限制\n" +
		strings.Repeat("此为离线覆盖夹具：来源 execution:baseline 与 execution:fofa-empty-result 已留存，覆盖结论仅针对本轮登记范围，不外推到未测试目标或其他身份。\n", 5)
}

func TestDecideCoverageBlocksReportUntilLedgerCloses(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "active")
	in := Input{ConversationID: conversation, AssistantMessageID: message, Response: coverageReportFixture("测试报告已经整理完成。")}
	d := Decide(db, in)
	if d.Finalizable || d.CompletionReason != ReasonCoverageIncomplete || len(d.MissingChecks) == 0 {
		t.Fatalf("open ledger finalized: %+v", d)
	}
	persistCoverage(t, db, project, conversation, "passed")
	d = Decide(db, in)
	if !d.Finalizable || len(d.EvidenceRefs) == 0 {
		t.Fatalf("closed ledger rejected: %+v", d)
	}
}

func TestDecideCoverageIgnoresOtherConversationAndOldTurn(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	other, err := db.CreateConversation("other", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	persistCoverage(t, db, project, other.ID, "active")
	in := Input{ConversationID: conversation, AssistantMessageID: message, Response: "这是普通问答的完整回答。"}
	if d := Decide(db, in); !d.Finalizable {
		t.Fatalf("other conversation polluted decision: %+v", d)
	}
	in.RequireCoverageEvidence = true
	if d := Decide(db, in); d.Finalizable || !strings.Contains(strings.Join(d.MissingChecks, "\n"), "manifest") {
		t.Fatalf("other conversation satisfied required ledger: %+v", d)
	}
	persistCoverage(t, db, project, conversation, "active")
	_, err = db.Exec("UPDATE project_facts SET updated_at = '2000-01-01T00:00:00Z' WHERE source_conversation_id = ?", conversation)
	if err != nil {
		t.Fatal(err)
	}
	in.RequireCoverageEvidence = false
	if d := Decide(db, in); !d.Finalizable {
		t.Fatalf("old turn blocked ordinary answer: %+v", d)
	}
}

func TestDecideCoverageBlocksMissingFOFAEvenWithOtherSources(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "passed")
	if _, err := db.Exec("DELETE FROM project_facts WHERE project_id = ? AND fact_key = ?", project, "recon/source/run-a/fofa_search/example"); err != nil {
		t.Fatal(err)
	}
	in := Input{ConversationID: conversation, AssistantMessageID: message, Response: coverageReportFixture("信息收集与覆盖已完成。")}
	d := Decide(db, in)
	if d.Finalizable || d.CompletionReason != ReasonCoverageIncomplete || !strings.Contains(strings.Join(d.MissingChecks, "\n"), "fofa_search") {
		t.Fatalf("missing FOFA source did not block finalization: %+v", d)
	}
	persistCoverage(t, db, project, conversation, "passed")
	if d := Decide(db, in); !d.Finalizable {
		t.Fatalf("FOFA evidence repair did not unblock finalization: %+v", d)
	}
}

func TestClosedCoverageStillRequiresReportBody(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "passed")
	for _, submitted := range []bool{false, true} {
		d := Decide(db, Input{ConversationID: conversation, AssistantMessageID: message, Response: "已完成。", ReportSubmitted: submitted})
		if d.Finalizable || d.CompletionReason != ReasonIncompleteCandidate {
			t.Fatalf("short notice bypassed report requirement: %+v", d)
		}
	}
}

func TestDecideExplicitCoverageFailsClosedWithoutDatabase(t *testing.T) {
	d := Decide(nil, Input{Response: "完整报告。", RequireCoverageEvidence: true})
	if d.Finalizable || d.CompletionReason != ReasonCoverageIncomplete {
		t.Fatalf("required coverage silently bypassed: %+v", d)
	}
}
