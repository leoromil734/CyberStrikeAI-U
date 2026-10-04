package agentfinalizer

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
)

func assertStoppedDeliveryPreservesDecision(t *testing.T, before, got Decision) {
	t.Helper()
	if !got.DeliveryAvailable || !got.RunTerminated || got.DeliveryKind != DeliveryKindPartialReport || got.DeliveryText == "" || got.Finalizable || got.Finalized || got.EvidenceVerified {
		t.Fatalf("invalid partial delivery: %+v", got)
	}
	want := before
	want.DeliveryAvailable, want.RunTerminated = true, true
	want.DeliveryKind, want.DeliveryText = DeliveryKindPartialReport, got.DeliveryText
	want.Finalizable, want.Finalized, want.EvidenceVerified = false, false, false
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("partial delivery changed the original decision:\nwant %+v\ngot  %+v", want, got)
	}
	if utf8.RuneCountInString(got.DeliveryText) > stoppedReportMaxRunes || !strings.Contains(got.DeliveryText, "## 恢复建议") {
		t.Fatal("report exceeded its bound or lost recovery advice")
	}
}

func saveStoppedTestExecution(t *testing.T, db *database.DB, cid, id, tool, status string) {
	t.Helper()
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: id, ConversationID: cid, ToolName: tool, Status: status, StartTime: time.Now(),
		Arguments: map[string]interface{}{"password": "PRIVATE_ARGUMENT_SECRET"},
		Result:    &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "PRIVATE_RAW_RESULT"}}},
		Error:     "PRIVATE_RAW_ERROR", PartialOutput: "PRIVATE_PARTIAL_LOG"}); err != nil {
		t.Fatal(err)
	}
}

func TestPartialDeliveryUnavailableStorageStillDelivers(t *testing.T) {
	base := Decision{ConversationID: "missing-conversation", Status: StatusFailed, CompletionReason: ReasonFailed,
		FinalText: "# 全部安全，6/6 passed", MissingChecks: []string{"unknown check with PRIVATE_DIAGNOSTIC"},
		EvidenceRefs: []string{"mcp_execution:foreign-reference"}, PendingExecutionIDs: []string{"pending-before-failure"},
		PendingToolRuns: []string{"PRIVATE_PENDING_SNAPSHOT"}, CoverageBlockers: []string{"PRIVATE_BLOCKER"}}
	for _, status := range []string{StatusBlocked, StatusFailed, StatusCancelled, "timeout"} {
		for _, db := range []*database.DB{nil, {}} {
			d := base
			d.Status = status
			got := PrepareStoppedDelivery(db, d)
			assertStoppedDeliveryPreservesDecision(t, d, got)
			for _, want := range []string{"数据库不可用", "无法核实", "登记数量未知", "不将未知数量记为零", "未核验", "待完成"} {
				if !strings.Contains(got.DeliveryText, want) {
					t.Fatalf("fallback missing %q: %s", want, got.DeliveryText)
				}
			}
			for _, secret := range []string{"6/6 passed", "PRIVATE_", "foreign-reference"} {
				if strings.Contains(got.DeliveryText, secret) {
					t.Fatalf("unverified/free text leaked: %q", secret)
				}
			}
		}
	}

	db, cid := partialDeliveryFixture(t)
	for _, id := range []string{"", "deleted-or-missing"} {
		d := base
		d.ConversationID = id
		got := PrepareStoppedDelivery(db, d)
		assertStoppedDeliveryPreservesDecision(t, d, got)
		if !strings.Contains(got.DeliveryText, "无法") || strings.Contains(got.DeliveryText, "尚无已登记漏洞") {
			t.Fatalf("unavailable identity turned into zero results: %s", got.DeliveryText)
		}
	}
	base.ConversationID = cid
	db.Close()
	got := PrepareStoppedDelivery(db, base)
	assertStoppedDeliveryPreservesDecision(t, base, got)
	if !strings.Contains(got.DeliveryText, "会话信息读取失败") {
		t.Fatal("closed database was not explained")
	}
}

func TestPartialDeliveryPreservesSavedResultsAndSpecificGaps(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	project, err := db.CreateProject(&database.Project{Name: "current application", ScopeJSON: `{"targets":["https://app.example.test/api"],"exclude":["https://app.example.test/admin"]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(cid, project.ID); err != nil {
		t.Fatal(err)
	}
	saveStoppedTestExecution(t, db, cid, "scan-httpx-1", "httpx", mcp.ToolExecutionStatusCompleted)
	saveStoppedTestExecution(t, db, cid, "scan-nuclei-1", "nuclei", mcp.ToolExecutionStatusFailed)
	finding, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: cid, Title: "Authorization finding", Severity: "high", Status: "open", Evidence: "PRIVATE_VULNERABILITY_EVIDENCE"})
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{ConversationID: cid, Status: StatusBlocked, CompletionReason: ReasonCoverageIncomplete,
		FinalText: "所有检查已通过，6/6 passed", EvidenceRefs: []string{"mcp_execution:scan-httpx-1"}, ReportSubmitted: true,
		MissingChecks:         []string{"recon/endpoint/current/users: endpoint still needs baseline and risk mapping", "original ingestion failed: execution:scan-nuclei-1; PRIVATE_INGESTION_ERROR"},
		CoverageProgressKnown: true, CoverageInventoryGroups: 9, CoverageMappedGroups: 2, CoverageUnresolvedGroups: 7, CoverageEvidenceExecutions: 1}
	got := PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	for _, want := range []string{"offline partial report", "current application", "app.example.test/api", "app.example.test/admin", "scan-httpx-1", "scan-nuclei-1", "工具：httpx；状态：completed；记录数：1", "工具：nuclei；状态：failed；记录数：1", "Authorization finding", finding.ID, "登记状态：open", "端点基线", "recon/endpoint/current/users", "原始结果入库", "**9 组**", "**7 组**"} {
		if !strings.Contains(got.DeliveryText, want) {
			t.Fatalf("saved result missing %q:\n%s", want, got.DeliveryText)
		}
	}
	for _, bad := range []string{"PRIVATE_", "6/6 passed", "所有检查已通过"} {
		if strings.Contains(got.DeliveryText, bad) {
			t.Fatalf("raw text/credentials promoted: %q", bad)
		}
	}
}

func TestPartialDeliveryPartialQueryFailureRetainsReadableResults(t *testing.T) {
	for _, table := range []string{"tool_executions", "vulnerabilities"} {
		t.Run(table, func(t *testing.T) {
			db, cid := partialDeliveryFixture(t)
			saveStoppedTestExecution(t, db, cid, "saved-execution", "httpx", mcp.ToolExecutionStatusCompleted)
			if _, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: cid, Title: "Readable finding", Severity: "medium", Status: "false_positive"}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			d := Decision{ConversationID: cid, Status: StatusFailed}
			got := PrepareStoppedDelivery(db, d)
			assertStoppedDeliveryPreservesDecision(t, d, got)
			if !strings.Contains(got.DeliveryText, "读取不完整／无法核实") {
				t.Fatal("partial read failure was hidden")
			}
			if table == "tool_executions" {
				if !strings.Contains(got.DeliveryText, "Readable finding") || !strings.Contains(got.DeliveryText, reportInline("false_positive")) || !strings.Contains(got.DeliveryText, "工具执行总数及各状态数量无法核实") {
					t.Fatal("tool read failure erased findings or pretended zero tools")
				}
			} else if !strings.Contains(got.DeliveryText, "saved-execution") || !strings.Contains(got.DeliveryText, "登记数量未知") || strings.Contains(got.DeliveryText, "尚无已登记漏洞") {
				t.Fatal("finding read failure erased tools or pretended zero findings")
			}
		})
	}
}

func TestPartialDeliveryIsolatesConversationAndCurrentProject(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	project, err := db.CreateProject(&database.Project{Name: "current project"})
	if err != nil {
		t.Fatal(err)
	}
	foreignProject, err := db.CreateProject(&database.Project{Name: "PRIVATE_FOREIGN_PROJECT"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(cid, project.ID); err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateConversation("PRIVATE_OTHER_TITLE", database.ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	saveStoppedTestExecution(t, db, cid, "current-execution", "httpx", mcp.ToolExecutionStatusCompleted)
	saveStoppedTestExecution(t, db, other.ID, "PRIVATE_OTHER_EXECUTION", "PRIVATE_OTHER_TOOL", mcp.ToolExecutionStatusRunning)
	for _, finding := range []*database.Vulnerability{
		{ConversationID: cid, ProjectID: project.ID, Title: "Current finding", Severity: "info", Status: "open"},
		{ConversationID: other.ID, ProjectID: project.ID, Title: "PRIVATE_SAME_PROJECT_OTHER_CONVERSATION", Severity: "critical", Status: "confirmed"},
		{ConversationID: cid, ProjectID: foreignProject.ID, Title: "PRIVATE_WRONG_PROJECT", Severity: "critical", Status: "confirmed"},
		{ProjectID: project.ID, Title: "PRIVATE_UNATTRIBUTED_FINDING", Severity: "critical", Status: "confirmed"},
	} {
		if _, err := db.CreateVulnerability(finding); err != nil {
			t.Fatal(err)
		}
	}
	d := Decision{ConversationID: cid, Status: StatusBlocked, EvidenceRefs: []string{"mcp_execution:PRIVATE_OTHER_EXECUTION"}}
	got := PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	if strings.Contains(got.DeliveryText, "PRIVATE_") || !strings.Contains(got.DeliveryText, "Current finding") || !strings.Contains(got.DeliveryText, "current-execution") || !strings.Contains(got.DeliveryText, "共登记 1 条") {
		t.Fatalf("conversation/project boundary failed: %s", got.DeliveryText)
	}
	// Orphan tool rows must not make a deleted conversation look readable.
	if _, err := db.Exec("DELETE FROM conversations WHERE id = ?", cid); err != nil {
		t.Fatal(err)
	}
	got = PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	if !strings.Contains(got.DeliveryText, "会话已删除或不存在") || strings.Contains(got.DeliveryText, "current-execution") || strings.Contains(got.DeliveryText, "Current finding") {
		t.Fatal("deleted conversation leaked residual records")
	}
}

func TestPartialDeliveryCancellationAndTimeoutDoNotUpgradeStaleFlags(t *testing.T) {
	for _, status := range []string{StatusBlocked, StatusFailed, StatusCancelled, "timeout"} {
		d := Decision{Status: status, CompletionReason: ReasonPendingTools, Finalizable: true, Finalized: true, EvidenceVerified: true,
			PendingExecutionIDs: []string{"pending-id"}, PendingToolRuns: []string{"pending-tool"}, FinalText: "# 6/6 passed", MissingChecks: []string{"workflow is awaiting HITL approval"}}
		got := PrepareStoppedDelivery(nil, d)
		assertStoppedDeliveryPreservesDecision(t, d, got)
		if !strings.Contains(got.DeliveryText, stoppedStatusLabel(status)) {
			t.Fatalf("lost terminal state %s", status)
		}
	}
	// A cancellation is terminal even if the previous diagnostic was approval.
	d := Decision{Status: StatusCancelled, CompletionReason: ReasonAwaitingHITL}
	assertStoppedDeliveryPreservesDecision(t, d, PrepareStoppedDelivery(nil, d))
}

func TestPartialDeliveryEscapesDatabaseAndDoesNotCopyCandidate(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	malicious := "<img src=x onerror=alert(1)>\n![track](https://outside.invalid/pixel) **safe** | x"
	if _, err := db.Exec("UPDATE conversations SET title = ? WHERE id = ?", malicious, cid); err != nil {
		t.Fatal(err)
	}
	project, err := db.CreateProject(&database.Project{Name: malicious, ScopeJSON: `{"targets":["https://user:PRIVATE_URL_PASSWORD@app.example.test/api?token=PRIVATE_QUERY#PRIVATE_FRAGMENT"],"exclude":["<script>alert(1)</script>"],"notes":"PRIVATE_NOTES_PASSWORD"}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(cid, project.ID); err != nil {
		t.Fatal(err)
	}
	saveStoppedTestExecution(t, db, cid, "safe-id", malicious, mcp.ToolExecutionStatusCompleted)
	if _, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: cid, Title: malicious, Severity: "info", Status: malicious}); err != nil {
		t.Fatal(err)
	}
	d := Decision{ConversationID: cid, Status: StatusBlocked, FinalText: "<script>PRIVATE_CANDIDATE</script> 全部安全 6/6 passed", CompletionReason: "password=PRIVATE_REASON"}
	got := PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	for _, unsafe := range []string{"<img", "<script", "![track]", "**safe**", "PRIVATE_", "6/6 passed"} {
		if strings.Contains(got.DeliveryText, unsafe) {
			t.Fatalf("unsafe text leaked %q: %s", unsafe, got.DeliveryText)
		}
	}
	if !strings.Contains(got.DeliveryText, "&lt;img") || !strings.Contains(got.DeliveryText, "app.example.test/api") {
		t.Fatal("escaping erased useful safe metadata")
	}
}

func TestPartialDeliveryUnknownProgressRetainsObservationsWithoutInventingTotals(t *testing.T) {
	d := Decision{Status: StatusCancelled, CoverageInventoryGroups: 7, CoverageUnresolvedGroups: 7, CoverageEvidenceExecutions: 2}
	got := PrepareStoppedDelivery(nil, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	if !strings.Contains(got.DeliveryText, "仅停止时观测值") || !strings.Contains(got.DeliveryText, "库存 7 组") || strings.Contains(got.DeliveryText, "独立候选库存共") {
		t.Fatal("unknown progress was discarded or promoted into known totals")
	}
	d.CoverageProgressKnown = true
	d.CoverageMappedGroups = 6 // Inconsistent with the seven unresolved groups.
	got = PrepareStoppedDelivery(nil, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	if strings.Contains(got.DeliveryText, "独立候选库存共") {
		t.Fatal("inconsistent snapshot rendered as known coverage")
	}
}

func TestPartialDeliveryReadOnlyWithGovernedAssessment(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	project, err := db.CreateProject(&database.Project{Name: "read-only project"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(cid, project.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BeginAssessmentRun(cid, project.ID, "", "", database.AssessmentModeComprehensive, "readonly-assessment"); err != nil {
		t.Fatal(err)
	}
	saveStoppedTestExecution(t, db, cid, "readonly-execution", "httpx", mcp.ToolExecutionStatusRunning)
	db.DB.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA query_only = ON"); err != nil {
		t.Fatal(err)
	}
	d := Decision{ConversationID: cid, Status: StatusCancelled, CompletionReason: ReasonCancelled}
	got := PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	if !strings.Contains(got.DeliveryText, "readonly-execution") || strings.Contains(got.DeliveryText, "读取失败") || got.CoverageProgressKnown {
		t.Fatal("read-only delivery failed or silently re-ran the coverage gate")
	}
	run, err := db.LatestAssessmentRun(cid)
	if err != nil || run == nil || run.Status != "running" {
		t.Fatalf("report changed assessment state: %+v, %v", run, err)
	}
}

func TestPartialDeliveryBoundsHostileMetadataWithoutDroppingSections(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	huge := strings.Repeat("<&*", 2000)
	if _, err := db.Exec("UPDATE conversations SET title = ? WHERE id = ?", huge, cid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < stoppedFindingLimit; i++ {
		saveStoppedTestExecution(t, db, cid, fmt.Sprintf("bounded-execution-%d", i), huge+fmt.Sprint(i), huge)
		if _, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: cid, Title: huge, Severity: huge, Status: huge}); err != nil {
			t.Fatal(err)
		}
	}
	d := Decision{ConversationID: cid, Status: "timeout", CompletionReason: "timeout", MissingChecks: []string{"recon/endpoint/run-a/users: endpoint still needs baseline and risk mapping"}}
	got := PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	for _, heading := range []string{"## 任务与停止原因", "已超时，评估未完成", "## 数据边界与可核实性", "## 已保存的工具执行", "可核对执行 ID", "## 已登记的发现", "## 覆盖进度与具体缺口", "端点基线", "## 恢复建议", "本节展示已达长度上限"} {
		if !strings.Contains(got.DeliveryText, heading) {
			t.Fatalf("oversized metadata removed required section %q", heading)
		}
	}
}

func TestPartialDeliveryBoundsRowsAndRetainsPendingID(t *testing.T) {
	db, cid := partialDeliveryFixture(t)
	for i := 0; i < stoppedExecutionLimit+5; i++ {
		saveStoppedTestExecution(t, db, cid, fmt.Sprintf("exec-%02d", i), fmt.Sprintf("tool-%02d", i), mcp.ToolExecutionStatusCompleted)
	}
	saveStoppedTestExecution(t, db, cid, "old-pending-id", "old-pending-tool", mcp.ToolExecutionStatusRunning)
	if _, err := db.Exec("UPDATE tool_executions SET start_time = ? WHERE id = ?", time.Now().Add(-time.Hour), "old-pending-id"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < stoppedFindingLimit+2; i++ {
		if _, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: cid, Title: fmt.Sprintf("Finding %02d", i), Severity: "low", Status: "open"}); err != nil {
			t.Fatal(err)
		}
	}
	d := Decision{ConversationID: cid, Status: StatusBlocked}
	got := PrepareStoppedDelivery(db, d)
	assertStoppedDeliveryPreservesDecision(t, d, got)
	for _, want := range []string{"累计保存 26 条", "共登记 22 条", "其余执行 ID 未展开", "其余工具／状态分组未展开", "执行 ID：old-pending-id"} {
		if !strings.Contains(got.DeliveryText, want) {
			t.Fatalf("bounded report missing %q", want)
		}
	}
	if strings.Count(got.DeliveryText, "- 执行 ID：") != stoppedExecutionLimit || strings.Count(got.DeliveryText, "登记状态：") != stoppedFindingLimit {
		t.Fatal("display limits were not enforced")
	}
}
