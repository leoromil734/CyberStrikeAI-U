package multiagent

import (
	"encoding/json"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/schema"
)

// CoverageContinuationHeader identifies an internal repair segment, not a new
// user request. Keep this shared with the handler that creates the instruction.
const CoverageContinuationHeader = "【系统自动续跑 / Auto resume】\n结构化覆盖检查尚未通过。只补当前评估缺口，不重复已完成步骤，不扩大授权范围，保留用户排除项。查阅 pentest-blackboard/references/coverage-contract.md 并读取相应事实；blocked/N/A 必须有原始证据和具体原因，不得把未测改成已覆盖。\n修复完成后必须重新输出本次任务的完整最终报告（含结论、覆盖、发现、负结果与限制），同步必要更正；不要只回复计数已对齐或账本已修复。\n"

const coverageRepairInstructionPrefix = "【系统自动续跑 / Auto resume】\n结构化覆盖检查尚未通过。"

var assessmentHeadingPattern = regexp.MustCompile(`(?m)^#{1,6}\s+\S`)

// FinalReportAfterCoverageRepair preserves the report from this request when a
// successful internal coverage repair returned only a bookkeeping notice. The
// caller must validate the latest runtime/coverage state before using this text.
// Real user messages are a hard boundary; reports from older requests and
// arbitrary tool output are never promoted (only the explicit exit report).
// Keep the repair notice as an explicit addendum so the original report and the
// latest inventory corrections both remain visible. The returned flag identifies
// a repair-only response even if no report can be
// recovered, allowing the caller to request a report rather than deliver a notice.
func FinalReportAfterCoverageRepair(response, traceJSON string) (text string, repairOnly bool) {
	if !isCoverageRepairNotice(response) || strings.TrimSpace(traceJSON) == "" {
		return response, false
	}
	var msgs []*schema.Message
	if err := json.Unmarshal([]byte(traceJSON), &msgs); err != nil {
		return response, false
	}
	lastUser := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i] != nil && msgs[i].Role == schema.User {
			lastUser = i
			break
		}
	}
	if lastUser < 0 || !isReportRecoveryInstruction(msgs[lastUser].Content) {
		return response, false
	}
	for i := lastUser - 1; i >= 0; i-- {
		m := msgs[i]
		if m == nil {
			continue
		}
		if m.Role == schema.User {
			if isReportRecoveryInstruction(m.Content) {
				continue
			}
			break
		}
		candidate := ""
		switch m.Role {
		case schema.Assistant:
			if len(m.ToolCalls) == 0 {
				candidate = m.Content
			} else {
				candidate = einoExtractExitFinalFromAssistantToolCalls(m)
			}
		case schema.Tool:
			if strings.EqualFold(strings.TrimSpace(m.ToolName), "exit") && !strings.HasPrefix(strings.TrimSpace(m.Content), einomcp.ToolErrorPrefix) {
				candidate = m.Content
			}
		}
		if !isAssessmentReport(candidate) {
			continue
		}
		return strings.TrimSpace(candidate) + "\n\n## 最终覆盖检查补充\n\n" + strings.TrimSpace(response), true
	}
	return response, true
}

func isReportRecoveryInstruction(text string) bool {
	text = strings.TrimSpace(text)
	return strings.HasPrefix(text, coverageRepairInstructionPrefix) ||
		strings.HasPrefix(text, "【系统交付修复 / Final report required】")
}

func isCoverageRepairNotice(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" || len([]rune(text)) > 1200 || isAssessmentReport(text) {
		return false
	}
	lower := strings.ToLower(text)
	coverage := strings.Contains(text, "覆盖计数") || strings.Contains(text, "覆盖账本") ||
		strings.Contains(text, "评估计数") || strings.Contains(text, "库存计数") ||
		strings.Contains(lower, "coverage count") || strings.Contains(lower, "coverage ledger") ||
		strings.Contains(lower, "inventory count")
	repaired := strings.Contains(text, "已对齐") || strings.Contains(text, "已修复") ||
		strings.Contains(text, "已改为") || strings.Contains(text, "已更新") ||
		strings.Contains(text, "已按检查项对齐") || strings.Contains(text, "已更正") ||
		strings.Contains(lower, "aligned") || strings.Contains(lower, "corrected") ||
		strings.Contains(lower, "updated") || strings.Contains(lower, "fixed")
	return coverage && repaired
}

func isAssessmentReport(text string) bool {
	if len([]rune(strings.TrimSpace(text))) < 250 || len(assessmentHeadingPattern.FindAllStringIndex(text, -1)) < 2 {
		return false
	}
	lower := strings.ToLower(text)
	groups := [][]string{
		{"风险概览", "结论摘要", "评估结论", "测试结论", "executive summary", "risk overview"},
		{"## 资产", "覆盖账本", "资产覆盖", "测试范围", "source coverage", "asset coverage", "scope"},
		{"已验证结论", "已确认发现", "漏洞详情", "复现证据", "测试结果", "findings", "verified results"},
		{"负结果", "范围限制", "限制", "修复建议", "limitations", "negative results", "remediation"},
	}
	matched := 0
	for _, group := range groups {
		for _, marker := range group {
			if strings.Contains(lower, marker) {
				matched++
				break
			}
		}
	}
	return matched >= 3
}
