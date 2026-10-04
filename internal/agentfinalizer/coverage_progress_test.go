package agentfinalizer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
)

func seedProgressInventory(t *testing.T, db *database.DB, project, conversation, assessment string, count int) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`INSERT INTO recon_inventory
		(id,project_id,conversation_id,owner,scope_id,assessment_id,kind,host,raw_host,ip,port,raw_port,protocol,
		raw_url,raw_path,method,service_name,template_id,severity,scope_state,candidate_only,first_source_id,
		artifact_id,execution_id,source_offset,source_length,source_line)
		VALUES (?,?,?,'fixture-owner','fixture-scope',?,'endpoint','inventory.invalid','inventory.invalid','',443,'443','https',
		?,?,'GET','','','','unknown',1,'fixture-source','fixture-artifact','archive',0,1,1)`)
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	for i := 0; i < count; i++ {
		if _, err := statement.Exec(fmt.Sprintf("%s-%s-%d", conversation, assessment, i), project, conversation, assessment,
			fmt.Sprintf("https://inventory.invalid/item/%d", i), fmt.Sprintf("/item/%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func seedProgressSource(t *testing.T, db *database.DB, project, conversation, assessment string, source database.AssessmentSourceMetadata) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO recon_sources
		(id,execution_id,artifact_id,project_id,conversation_id,owner,scope_id,assessment_id,sha256,tool,format,
		parser_version,completion,state,reason,stats_json,inserted_json,observed_at_ms,expires_at_ms)
		VALUES (?,?,'fixture-artifact',?,?,'fixture-owner','fixture-scope',?,'fixture-sha',?,'jsonl','offline-fixture/v1',?,?,?,'{}','{}',1,?)`,
		source.ID, source.ExecutionID, project, conversation, assessment, source.Tool, source.Completion, source.State, source.Reason, source.ExpiresAtMS)
	if err != nil {
		t.Fatal(err)
	}
}

func progressSource(id, executionID, tool string) database.AssessmentSourceMetadata {
	return database.AssessmentSourceMetadata{ID: id, ExecutionID: executionID, Tool: tool, State: evidence.Parsed, Completion: evidence.Complete}
}

func progressFacts(i int, status, proof string) []coverage.Fact {
	endpointID, _ := coverage.EndpointKey(fmt.Sprintf("https://inventory.invalid/item/%d", i), "GET")
	endpointKey, riskKey := "recon/endpoint/run-a/"+endpointID, fmt.Sprintf("recon/risk/run-a/item-%d", i)
	endpoint, _ := json.Marshal(map[string]any{
		"assessment_id": "run-a", "endpoint_url": fmt.Sprintf("https://inventory.invalid/item/%d", i),
		"host": "inventory.invalid", "method": "GET", "path": fmt.Sprintf("/item/%d", i),
		"runtime_status": "risk-mapped", "evidence": proof, "risk_units": []string{riskKey},
	})
	risk, _ := json.Marshal(map[string]any{
		"assessment_id": "run-a", "endpoint_key": endpointKey, "risk_family": "access-control", "identity": "anonymous",
		"status": status, "evidence": proof, "reason": "offline fixture classification, not a real test",
	})
	return []coverage.Fact{{Key: endpointKey, Body: string(endpoint)}, {Key: riskKey, Body: string(risk)}}
}

func checkProgressFixture(t *testing.T, db *database.DB, project, conversation string, facts []coverage.Fact) (CoverageProgress, coverage.Report) {
	t.Helper()
	report := coverage.Report{Active: true}
	progress := checkIndependentInventory(db, project, conversation, "run-a", facts, &report)
	return progress, report
}

func TestCoverageRepairScopeThresholdDoesNotTruncateInventory(t *testing.T) {
	for _, total := range []int{0, MaxAutomaticCoverageRepairGroups, MaxAutomaticCoverageRepairGroups + 1, 1668} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			db, project, conversation, _ := coverageTestDB(t)
			seedProgressInventory(t, db, project, conversation, "run-a", total)
			progress, report := checkProgressFixture(t, db, project, conversation, nil)
			if !progress.Known || progress.InventoryGroups != total || progress.UnresolvedGroups != total || progress.MappedGroups != 0 || progress.RepairBlocked != (total > MaxAutomaticCoverageRepairGroups) {
				t.Fatalf("inventory/boundary changed: %+v", progress)
			}
			if total == 0 && len(report.Missing) != 0 {
				t.Fatalf("known empty inventory created gaps: %v", report.Missing)
			}
			if total > MaxAutomaticCoverageRepairGroups {
				feedback := strings.Join(report.Missing, "\n")
				for _, required := range []string{fmt.Sprintf("total=%d", total), "diagnostic samples", "automatic coverage repair blocked", "verified results", "untested/pending-classification", "authorized scope, freshness and business templates", "Do not generate per-URL N/A"} {
					if !strings.Contains(feedback, required) {
						t.Fatalf("missing conservative feedback %q: %s", required, feedback)
					}
				}
				if got := strings.Count(feedback, "has no matching ledger disposition"); got != independentInventorySampleLimit {
					t.Fatalf("wrong diagnostic sample size: %d", got)
				}
			}
		})
	}
}

func TestCoverageProgressHistorical25735CannotBecomeNARepairQueue(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	seedProgressInventory(t, db, project, conversation, "run-a", 25735)
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("archive-source", "archive", "gau"))
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("baseline-source", "baseline", "httpx"))
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("fofa-source", "fofa-empty-result", "fofa"))
	before, _ := checkProgressFixture(t, db, project, conversation, nil)
	// This deterministic offline fixture models the historical URL-by-URL
	// bookkeeping loop. Even copied real source references do not make an
	// N/A-only ledger dispose of raw candidates.
	facts := make([]coverage.Fact, 0, 25735*2)
	for i := 0; i < 25735; i++ {
		facts = append(facts, progressFacts(i, "not-applicable", "execution:baseline")...)
	}
	for _, written := range []int{699, 25735} {
		progress, report := checkProgressFixture(t, db, project, conversation, facts[:written*2])
		if progress != before || !progress.RepairBlocked || progress.UnresolvedGroups != 25735 {
			t.Fatalf("%d N/A pairs manufactured progress: before=%+v after=%+v", written, before, progress)
		}
		if !strings.Contains(strings.Join(report.Missing, "\n"), "25705 additional independent discovery groups") {
			t.Fatalf("full missing count was truncated: %v", report.Missing)
		}
	}
	// Lowering the manifest to zero cannot hide the separate original inventory.
	persistCoverage(t, db, project, conversation, "passed")
	if _, err := db.BeginAssessmentRun(conversation, project, "", "", database.AssessmentModeComprehensive, "run-a"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "baseline", ToolName: "httpx", ConversationID: conversation, Status: "completed", StartTime: now, EndTime: &now}); err != nil {
		t.Fatal(err)
	}
	d := Decide(db, Input{ConversationID: conversation, AssistantMessageID: message, Response: "当前已验证成果与未测范围已整理。", MCPExecutionIDs: []string{"baseline"}})
	if d.Finalizable || d.CompletionReason != ReasonCoverageIncomplete || !d.CoverageProgressKnown || !d.CoverageRepairBlocked || d.CoverageInventoryGroups != 25735 || d.CoverageUnresolvedGroups != 25735 || d.CoverageEvidenceExecutions != 3 {
		t.Fatalf("self-consistent zero manifest bypassed raw inventory: %+v", d)
	}
}

func TestCoverageProgressCountsCurrentCompleteExecutionsNotActivities(t *testing.T) {
	db, project, conversation, _ := coverageTestDB(t)
	for _, source := range []database.AssessmentSourceMetadata{
		progressSource("live", "httpx-1", "httpx"), progressSource("live-duplicate-original", "httpx-1", "httpx"),
		progressSource("archive", "gau-1", "gau"), progressSource("empty-fofa", "fofa-1", "fofa"),
		progressSource("read", "read-1", "read_file"), progressSource("fact", "fact-1", "upsert_project_fact"),
		progressSource("missing-id", "", "httpx"),
	} {
		seedProgressSource(t, db, project, conversation, "run-a", source)
	}
	partial := progressSource("partial", "partial-1", "httpx")
	partial.Completion = evidence.Partial
	seedProgressSource(t, db, project, conversation, "run-a", partial)
	unparsed := progressSource("unparsed", "unparsed-1", "httpx")
	unparsed.State = evidence.Unsupported
	seedProgressSource(t, db, project, conversation, "run-a", unparsed)
	expired := progressSource("expired", "expired-1", "httpx")
	expired.ExpiresAtMS = time.Now().Add(-time.Hour).UnixMilli()
	seedProgressSource(t, db, project, conversation, "run-a", expired)
	seedProgressSource(t, db, project, conversation, "old-run", progressSource("old-assessment", "old-1", "httpx"))
	seedProgressSource(t, db, "other-project", conversation, "run-a", progressSource("foreign-project", "foreign-1", "httpx"))
	seedProgressSource(t, db, project, "other-conversation", "run-a", progressSource("foreign-conversation", "foreign-2", "httpx"))
	now := time.Now()
	for _, tool := range []string{"read_file", "upsert_project_fact", "httpx"} {
		if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "no-source-" + tool, ToolName: tool, ConversationID: conversation, Status: "completed", StartTime: now, EndTime: &now}); err != nil {
			t.Fatal(err)
		}
	}
	progress, _ := checkProgressFixture(t, db, project, conversation, progressFacts(0, "not-applicable", "execution:httpx-1"))
	if !progress.Known || progress.InventoryGroups != 0 || progress.MappedGroups != 0 || progress.UnresolvedGroups != 0 || progress.EvidenceExecutions != 3 || progress.RepairBlocked {
		t.Fatalf("non-evidence activities counted: %+v", progress)
	}
}

func TestCoverageMappedGroupsNeedEvidenceAndSubstantiveDisposition(t *testing.T) {
	db, project, conversation, _ := coverageTestDB(t)
	seedProgressInventory(t, db, project, conversation, "run-a", 2)
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("live-source", "scan-1", "httpx"))
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("archive-source", "archive", "gau"))
	for _, test := range []struct {
		name, status, proof string
		mapped              int
	}{
		{"actual", "covered", "execution:scan-1", 1},
		{"actual-negative", "negated", "source:live-source", 1},
		{"copied-na", "not-applicable", "execution:scan-1", 0},
		{"invented", "negated", "execution:made-up", 0},
		{"token-prefix", "covered", "execution:scan-10", 0},
		{"fact-proof", "covered", "project_fact:scan-1", 0},
		{"passive-negative", "negated", "execution:archive", 0},
		{"nonterminal", "active", "execution:scan-1", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := progressFacts(0, test.status, test.proof)
			facts = append(facts, facts...)                                            // duplicate bookkeeping cannot add a group
			facts = append(facts, progressFacts(99, "covered", "execution:scan-1")...) // not in original inventory
			progress, _ := checkProgressFixture(t, db, project, conversation, facts)
			if !progress.Known || progress.MappedGroups != test.mapped || progress.UnresolvedGroups != 2-test.mapped || progress.InventoryGroups != 2 || progress.EvidenceExecutions != 2 {
				t.Fatalf("untrusted disposition accepted: %+v", progress)
			}
		})
	}
}

func TestCoverageProgressReadFailuresAreUnknownNotEmpty(t *testing.T) {
	for _, table := range []string{"recon_inventory", "recon_sources", "result_ingestion_jobs"} {
		t.Run(table, func(t *testing.T) {
			db, project, conversation, _ := coverageTestDB(t)
			seedProgressInventory(t, db, project, conversation, "run-a", 101)
			if _, err := db.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			progress, report := checkProgressFixture(t, db, project, conversation, nil)
			if progress.Known || !progress.RepairBlocked || len(report.Missing) == 0 || !strings.Contains(strings.Join(report.Missing, "\n"), "zero remaining work must not be inferred") {
				t.Fatalf("read failure became zero/complete: %+v %+v", progress, report)
			}
			if table != "recon_inventory" && progress.InventoryGroups != 101 {
				t.Fatalf("other read failure hid known inventory: %+v", progress)
			}
		})
	}
}

func TestCoverageCappedInventoryRemainsUnknownEvenWithFewObservedGroups(t *testing.T) {
	db, project, conversation, _ := coverageTestDB(t)
	// Exercise the existing database read bound without a huge route fixture:
	// 200001 originals of one route are still an incomplete inventory read.
	_, err := db.Exec(`WITH RECURSIVE originals(n) AS (
		SELECT 0 UNION ALL SELECT n+1 FROM originals WHERE n < 200000
	) INSERT INTO recon_inventory
		(id,project_id,conversation_id,owner,scope_id,assessment_id,kind,host,raw_host,ip,port,raw_port,protocol,
		raw_url,raw_path,method,service_name,template_id,severity,scope_state,candidate_only,first_source_id,
		artifact_id,execution_id,source_offset,source_length,source_line)
		SELECT 'cap-' || n,?,?,'fixture-owner','fixture-scope','run-a','endpoint','inventory.invalid','inventory.invalid','',443,'443','https',
		'https://inventory.invalid/item/0','/item/0','GET','','','','unknown',1,'fixture-source','fixture-artifact','archive',0,1,1
		FROM originals`, project, conversation)
	if err != nil {
		t.Fatal(err)
	}
	progress, report := checkProgressFixture(t, db, project, conversation, nil)
	if progress.Known || !progress.RepairBlocked || progress.InventoryGroups != 1 || progress.UnresolvedGroups != 1 || !strings.Contains(strings.Join(report.Missing, "\n"), "bounded limit; completion cannot be claimed") {
		t.Fatalf("capped inventory became a small complete repair scope: %+v %+v", progress, report)
	}
}

func TestCoverageProgressPendingOrFailedIngestionStaysUnknown(t *testing.T) {
	for _, state := range []string{"pending", "failed"} {
		t.Run(state, func(t *testing.T) {
			db, project, conversation, _ := coverageTestDB(t)
			seedProgressInventory(t, db, project, conversation, "run-a", 1)
			if _, err := db.Exec(`INSERT INTO result_ingestion_jobs
				(execution_id,project_id,conversation_id,owner,assessment_id,scope_id,state,reason,updated_at_ms)
				VALUES ('fixture-ingestion',?,?,'fixture-owner','run-a','fixture-scope',?,'offline fixture',1)`, project, conversation, state); err != nil {
				t.Fatal(err)
			}
			progress, report := checkProgressFixture(t, db, project, conversation, nil)
			if progress.Known || !progress.RepairBlocked || progress.InventoryGroups != 1 || progress.UnresolvedGroups != 1 || len(report.Missing) == 0 {
				t.Fatalf("unfinished ingestion became known complete progress: %+v %+v", progress, report)
			}
		})
	}
}

func TestCoverageProgressMissingManifestStillChecksGovernedInventory(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	seedProgressInventory(t, db, project, conversation, "run-a", 101)
	if _, err := db.BeginAssessmentRun(conversation, project, "", "", database.AssessmentModeComprehensive, "run-a"); err != nil {
		t.Fatal(err)
	}
	for _, response := range []string{"当前已验证成果与未测范围已整理。", "接下来我会继续补写。"} {
		d := Decide(db, Input{ConversationID: conversation, AssistantMessageID: message, Response: response})
		if d.Finalizable || !d.CoverageProgressKnown || !d.CoverageRepairBlocked || d.CoverageInventoryGroups != 101 || d.CoverageUnresolvedGroups != 101 || !strings.Contains(strings.Join(d.MissingChecks, "\n"), "automatic coverage repair blocked") {
			t.Fatalf("missing manifest/evidence or incomplete response hid raw inventory: %+v", d)
		}
	}
}

func TestCoverageProgressNilAndLegacyCompatibility(t *testing.T) {
	d := Decide(nil, Input{Response: "普通问答已回答。"})
	if !d.Finalizable || d.CoverageProgressKnown || d.CoverageRepairBlocked {
		t.Fatalf("ordinary answer changed: %+v", d)
	}
	d = Decide(nil, Input{Response: "本次评估尚有未测范围。", RequireCoverageEvidence: true})
	if d.Finalizable || d.CoverageProgressKnown || !d.CoverageRepairBlocked {
		t.Fatalf("nil database was treated as known/empty coverage: %+v", d)
	}
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "passed")
	d = Decide(db, Input{Response: "旧版评估报告已整理。", ConversationID: conversation, AssistantMessageID: message})
	if !d.Finalizable || d.CoverageProgressKnown || d.CoverageRepairBlocked {
		t.Fatalf("legacy ledger gate changed: %+v", d)
	}
}

func TestCoverageValidFactsGrowthCannotCloseNAOnlyInventory(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	seedProgressInventory(t, db, project, conversation, "run-a", 2)
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("baseline-source", "baseline", "httpx"))
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("fofa-source", "fofa-empty-result", "fofa"))
	persistCoverage(t, db, project, conversation, "passed")
	if _, err := db.BeginAssessmentRun(conversation, project, "", "", database.AssessmentModeComprehensive, "run-a"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "baseline", ToolName: "httpx", ConversationID: conversation, Status: "completed", StartTime: now, EndTime: &now}); err != nil {
		t.Fatal(err)
	}
	in := Input{ConversationID: conversation, AssistantMessageID: message, Response: "当前成果与未测范围已整理。", MCPExecutionIDs: []string{"baseline"}}
	before := Decide(db, in)
	for i := 0; i < 2; i++ {
		for _, fact := range progressFacts(i, "not-applicable", "execution:baseline") {
			if _, err := db.UpsertProjectFact(&database.ProjectFact{ProjectID: project, SourceConversationID: conversation, FactKey: fact.Key, Body: fact.Body, Category: "recon", Confidence: "confirmed", Summary: "offline bookkeeping fixture"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.UpsertProjectFact(&database.ProjectFact{
		ProjectID: project, SourceConversationID: conversation, FactKey: "recon/assessment/run-a", Category: "recon", Confidence: "confirmed", Summary: "self-consistent counts",
		Body: "schema_version: 2\nassessment_id: run-a\nmode: comprehensive\nstatus: active\nscope_kind: single-url\nendpoint_count: 2\njs_count: 0\nrisk_unit_count: 2",
	}); err != nil {
		t.Fatal(err)
	}
	after := Decide(db, in)
	if after.CoverageValidFacts <= before.CoverageValidFacts {
		t.Fatalf("fixture did not reproduce ledger row growth: before=%+v after=%+v", before, after)
	}
	if after.Finalizable || !after.CoverageProgressKnown || after.CoverageInventoryGroups != 2 || after.CoverageUnresolvedGroups != 2 || after.CoverageMappedGroups != 0 || after.CoverageEvidenceExecutions != before.CoverageEvidenceExecutions {
		t.Fatalf("syntactically valid N/A facts manufactured closure/progress: %+v", after)
	}
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("new-live-source", "new-live-execution", "httpx"))
	withExecution := Decide(db, in)
	if withExecution.CoverageEvidenceExecutions != after.CoverageEvidenceExecutions+1 || withExecution.CoverageUnresolvedGroups != 2 || withExecution.Finalizable {
		t.Fatalf("actual source progress was lost or hid raw gaps: %+v", withExecution)
	}
}

func TestCoverageGovernedKnownEmptyInventoryRetainsExistingClosure(t *testing.T) {
	db, project, conversation, message := coverageTestDB(t)
	persistCoverage(t, db, project, conversation, "passed")
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("baseline-source", "baseline", "httpx"))
	seedProgressSource(t, db, project, conversation, "run-a", progressSource("fofa-source", "fofa-empty-result", "fofa"))
	if _, err := db.BeginAssessmentRun(conversation, project, "", "", database.AssessmentModeComprehensive, "run-a"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "baseline", ToolName: "httpx", ConversationID: conversation, Status: "completed", StartTime: now, EndTime: &now}); err != nil {
		t.Fatal(err)
	}
	d := Decide(db, Input{ConversationID: conversation, AssistantMessageID: message, Response: "未发现可用端点，当前来源已完成核验。", MCPExecutionIDs: []string{"baseline"}})
	if !d.Finalizable || !d.CoverageProgressKnown || d.CoverageRepairBlocked || d.CoverageInventoryGroups != 0 || d.CoverageUnresolvedGroups != 0 || d.CoverageEvidenceExecutions != 2 {
		t.Fatalf("known empty inventory regressed: %+v", d)
	}
}

func TestCompleteCoverageSourcesFreshnessAndStructuredBinding(t *testing.T) {
	live := progressSource("live-source", "live-execution", "httpx")
	expired := progressSource("expired-source", "expired-execution", "httpx")
	expired.ExpiresAtMS = 1000
	index := completeCoverageSources([]database.AssessmentSourceMetadata{live, expired}, 1000)
	if len(index.byExecution) != 1 {
		t.Fatalf("expiry boundary accepted: %+v", index)
	}
	for _, test := range []struct {
		fields map[string]any
		want   bool
	}{
		{map[string]any{"source_id": "live-source", "execution_id": "live-execution"}, true},
		{map[string]any{"source_id": "live-source", "execution_id": "other-execution"}, false},
		{map[string]any{"source_id": "invented", "evidence": "execution:live-execution"}, false},
		{map[string]any{"execution_id": "expired-execution", "evidence": "source:live-source"}, false},
		{map[string]any{"evidence": "mcp_execution:live-execution"}, true},
		{map[string]any{"evidence": "execution:live-execution-suffix"}, false},
	} {
		if got := index.corroborates(test.fields); got != test.want {
			t.Fatalf("incorrect execution binding for %v: %v", test.fields, got)
		}
	}
}

func TestCoverageProgressPayloadPreservesKnownZeroAndUnknown(t *testing.T) {
	for _, known := range []bool{false, true} {
		d := Decision{CoverageProgressKnown: known, CoverageRepairBlocked: !known}
		encoded, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(encoded, &payload); err != nil {
			t.Fatal(err)
		}
		for _, fields := range []map[string]any{payload, ResponsePayload(d, nil)} {
			if fields["coverageProgressKnown"] != known || fields["coverageRepairBlocked"] != !known {
				t.Fatalf("known state lost: %v", fields)
			}
			for _, name := range []string{"coverageInventoryGroups", "coverageUnresolvedGroups", "coverageMappedGroups", "coverageEvidenceExecutions"} {
				if _, ok := fields[name]; !ok {
					t.Fatalf("zero/unknown field omitted: %s in %v", name, fields)
				}
			}
		}
	}
}
