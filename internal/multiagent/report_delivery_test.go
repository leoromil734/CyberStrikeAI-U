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
	args, err := json.Marshal(map[string]string{"final_result": report})
	if err != nil {
		t.Fatal(err)
	}
	for _, exit := range []*schema.Message{
		schema.ToolMessage(report, "call-exit", schema.WithToolName("exit")),
		schema.AssistantMessage("", []schema.ToolCall{{ID: "call-exit", Function: schema.FunctionCall{Name: "exit", Arguments: string(args)}}}),
	} {
		trace := deliveryTraceJSON(t, schema.UserMessage("current task"), exit, schema.UserMessage(CoverageContinuationHeader))
		got, repairOnly := FinalReportAfterCoverageRepair(notice, trace)
		if !repairOnly || !strings.HasPrefix(got, report) {
			t.Fatalf("supervisor report not recovered: %q", got)
		}
	}
}
