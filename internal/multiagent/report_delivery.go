package multiagent

import (
	"encoding/json"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/projectprompt"

	"github.com/cloudwego/eino/schema"
)

const coverageRepairInstructionPrefix = "【系统自动续跑 / Auto resume】\n结构化覆盖检查尚未通过。"

// CoverageWorkContinuationHeader selects verification work without turning an
// incomplete inventory into a bookkeeping loop. Chosen high-value surface tests
// are explicitly allowed; only mechanical URL walking and fabricated facts are
// forbidden. Verified `curl -q -sSi` exchanges renew the work budget.
const CoverageWorkContinuationHeader = coverageRepairInstructionPrefix + "exit 是请求收尾，不是覆盖证明。本段优先对已发现的高价值面继续做实际验证，不补台账。保留用户排除项，不重复、不扩范围。\n" +
	"不要为库存机械补写 fact、不要把未测地址写成 N/A/negated/已覆盖、不要无选择地遍历 URL；对未测的高价值入口做有选择的基线/深入测试是允许且鼓励的。\n" +
	"对目标做 HTTP 测试时优先用 `curl -q -sSi <URL>`（单次直连、-i 保留响应头）：这类可核对的原件会计为真实进展并自动续期工作预算，python 脚本请求与管道组合不会被记录。\n" +
	projectprompt.HighImpactFindingPolicy + "\n" +
	"http-framework-test 只用于一个已选入口的对照，不用于遍历接口。符合筛选且确认危害后 record_vulnerability。没有可推进的高价值面或预算耗尽时交完整最终报告：成果、执行/原件引用、负结果、未测缺口与限制；覆盖不完整只能交阶段报告。Deep/Supervisor 根角色用 exit.final_result 提交报告全文。\n"

// CoverageContinuationHeader remains an alias for existing callers and saved
// traces; both paths must use the same finding selection and stop conditions.
const CoverageContinuationHeader = CoverageWorkContinuationHeader

var assessmentHeadingPattern = regexp.MustCompile(`(?m)^#{1,6}\s+\S`)

// FinalReportAfterCoverageRepair preserves the report from this request when a
// successful internal coverage repair returned only a bookkeeping notice. The
// caller must validate the latest runtime/coverage state before using this text.
// Real user messages are a hard boundary; reports from older requests and
// arbitrary tool output are never promoted (exit results need recorded root
// provenance; tool-call arguments are not execution evidence). This function
// recovers text only, never ReportSubmitted or a successful completion state.
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
			}
		case schema.Tool:
			candidate = historicalRootExitReport(m)
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

// IsAssessmentReportCandidate identifies a reasonably complete report-shaped
// candidate (including a draft or a partial assessment). It does not verify
// evidence, coverage, submission or finalization. Callers must retain missing
// checks and must not translate this predicate into a successful assessment.
func IsAssessmentReportCandidate(text string) bool {
	return isAssessmentReport(text)
}

// HasAssessmentReportBody checks delivery shape only, never evidence or safety.
func HasAssessmentReportBody(text string) bool {
	return len([]rune(strings.TrimSpace(text))) >= 250 && len(assessmentHeadingPattern.FindAllStringIndex(text, -1)) >= 2
}

func isAssessmentReport(text string) bool {
	if !HasAssessmentReportBody(text) {
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
