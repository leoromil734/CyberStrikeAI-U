package multiagent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

func deliveryTestReport() string {
	return "全面评估已完成。\n\n## 风险概览\n\n未确认跨越安全边界的漏洞。\n\n## Source Coverage\n\n" +
		strings.Repeat("已完成授权范围内的来源核对，原始证据保留，未测项不记为安全通过。\n", 8) +
		"\n## 已验证结论\n\n权限对照未证明越权。\n\n## 负结果与限制\n\n第三方资产与未授权入口未测。"
}

func deliveryTraceJSON(t *testing.T, msgs ...*schema.Message) string {
	t.Helper()
	data, err := json.Marshal(msgs)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestFinalReportInstructionRequiresRootSubmission(t *testing.T) {
	instruction := FormatFinalReportContinueUserMessage()
	for _, required := range []string{"Deep/Supervisor 根角色", "实际调用 exit", "报告全文写入 exit.final_result", "提交不代表覆盖通过", "阶段报告缺口"} {
		if !strings.Contains(instruction, required) {
			t.Fatalf("delivery instruction missing %q", required)
		}
	}
}

func TestIsAssessmentReportCandidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want bool
	}{
		{"complete draft", deliveryTestReport(), true},
		{"partial report with gaps", strings.ReplaceAll(deliveryTestReport(), "全面评估已完成。", "阶段报告：覆盖不完整，blocked/gap 仍存在。"), true},
		{"empty", "", false},
		{"diagnostics only", "覆盖账本已修复，库存计数已对齐。", false},
		{"heading without report body", "## 风险概览\n\n## Source Coverage\n\n待处理", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAssessmentReportCandidate(tc.text); got != tc.want {
				t.Fatalf("candidate=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestFinalReportAfterCoverageRepair(t *testing.T) {
	report := deliveryTestReport()
	notice := "覆盖计数已对齐。有效端点是 3 个，风险单元是 7 条。测试结论没有变化。"
	trace := deliveryTraceJSON(t,
		schema.UserMessage("全面评估 example.invalid"),
		schema.AssistantMessage(report, nil),
		schema.UserMessage(CoverageContinuationHeader+"- endpoint count mismatch"),
		schema.AssistantMessage("覆盖账本已修复，测试结论没有变化。", nil),
		schema.UserMessage(CoverageContinuationHeader+"- remaining count mismatch"),
		schema.UserMessage(FormatFinalReportContinueUserMessage()),
	)
	got, repairOnly := FinalReportAfterCoverageRepair(notice, trace)
	if !repairOnly || !strings.HasPrefix(got, report) || !strings.HasSuffix(got, notice) || !strings.Contains(got, "## 最终覆盖检查补充") {
		t.Fatalf("report lost after two repair segments: %q (repair=%v)", got, repairOnly)
	}
	if !strings.Contains(CoverageContinuationHeader, "完整最终报告") {
		t.Fatal("repair instruction must request the complete final deliverable")
	}
}

func TestCoverageContinuationRequiresInventoryAndPersistedEvidence(t *testing.T) {
	for _, required := range []string{
		"实际工作尚未执行", "upsert_project_fact", "body_fields", "recon/phase/*",
		"recon/source/*", "execution_id", "query_recon_inventory(execution_id, grouped=true, offset=0)",
		"inventory_group_key", "discovery-* 是数据库标识", "list_result_artifacts", "read_result_artifact",
		"库存候选本身不证明已测试", "未执行不得 passed", "回读核实", "完整最终报告",
	} {
		if !strings.Contains(CoverageContinuationHeader, required) {
			t.Errorf("continuation lost actionable evidence guidance: %s", required)
		}
	}
	// Retain the stable prefix so old saved repair segments remain recoverable.
	if !isReportRecoveryInstruction("【系统自动续跑 / Auto resume】\n结构化覆盖检查尚未通过。旧版诊断") ||
		!isReportRecoveryInstruction(CoverageContinuationHeader) {
		t.Fatal("coverage repair instruction compatibility lost")
	}
}

func TestFinalReportRecoveryBoundaries(t *testing.T) {
	report := deliveryTestReport()
	notice := "覆盖账本已修复。"
	cases := []struct {
		name       string
		response   string
		trace      string
		repairOnly bool
	}{
		{"invalid trace", notice, "not JSON", false},
		{"empty trace", notice, "[]", false},
		{"ordinary user asks counts", notice, deliveryTraceJSON(t, schema.AssistantMessage(report, nil), schema.UserMessage("只说明覆盖计数")), false},
		{"old user report", notice, deliveryTraceJSON(t, schema.UserMessage("old task"), schema.AssistantMessage(report, nil), schema.UserMessage("new task"), schema.UserMessage(CoverageContinuationHeader)), true},
		{"generic tool is not a report", notice, deliveryTraceJSON(t, schema.UserMessage("current task"), schema.ToolMessage(report, "call-file", schema.WithToolName("read_file")), schema.UserMessage(CoverageContinuationHeader)), true},
		{"failed exit output", notice, deliveryTraceJSON(t, schema.UserMessage("current task"), schema.ToolMessage("__CYBERSTRIKE_AI_TOOL_ERROR__\n"+report, "call-exit", schema.WithToolName("exit")), schema.UserMessage(CoverageContinuationHeader)), true},
		{"unexecuted exit arguments", notice, deliveryTraceJSON(t, schema.UserMessage("current task"), submissionExitCall(t, report), schema.UserMessage(CoverageContinuationHeader)), true},
		{"unscoped exit output", notice, deliveryTraceJSON(t, schema.UserMessage("current task"), toolExitMsg(report, "child-or-legacy-exit"), schema.UserMessage(CoverageContinuationHeader)), true},
		{"old submitted report before new request", notice, deliveryTraceJSON(t, schema.UserMessage("old task"), historicalExitMsg(report, "old-exit"), schema.UserMessage("new task"), schema.UserMessage(CoverageContinuationHeader)), true},
		{"no prior report", notice, deliveryTraceJSON(t, schema.UserMessage("current task"), schema.UserMessage(CoverageContinuationHeader)), true},
		{"already regenerated report", report, deliveryTraceJSON(t, schema.AssistantMessage(report+" old", nil), schema.UserMessage(CoverageContinuationHeader)), false},
		{"error text", "AI provider temporarily unavailable. Do not resend the same request.", deliveryTraceJSON(t, schema.AssistantMessage(report, nil), schema.UserMessage(CoverageContinuationHeader)), false},
		{"unfinished candidate", "接下来我核对清单。", deliveryTraceJSON(t, schema.AssistantMessage(report, nil), schema.UserMessage(CoverageContinuationHeader)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, repairOnly := FinalReportAfterCoverageRepair(tc.response, tc.trace)
			if got != tc.response || repairOnly != tc.repairOnly {
				t.Fatalf("unexpected recovery: got=%q repair=%v", got, repairOnly)
			}
		})
	}
}

func TestFinalReportRecoveryFromSupervisorExit(t *testing.T) {
	report := deliveryTestReport()
	notice := "Coverage counts are aligned."
	for _, exit := range []*schema.Message{
		historicalExitMsg(report, "call-exit"),
	} {
		trace := deliveryTraceJSON(t, schema.UserMessage("current task"), exit, schema.UserMessage(CoverageContinuationHeader))
		got, repairOnly := FinalReportAfterCoverageRepair(notice, trace)
		if !repairOnly || !strings.HasPrefix(got, report) {
			t.Fatalf("supervisor report not recovered: %q", got)
		}
	}
}
