package multiagent

import (
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
)

const defaultEmptyResponseContinueMaxAttempts = 5

// IsEinoEmptyResponseResult 判断 Run 是否以「未捕获助手正文」占位结束（非真实用户可见回复）。
func IsEinoEmptyResponseResult(result *RunResult) bool {
	if result == nil {
		return false
	}
	return isEinoEmptyResponseText(result.Response)
}

func isEinoEmptyResponseText(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return strings.Contains(s, "no assistant text was captured") ||
		strings.Contains(s, "未捕获到助手文本输出")
}

// IsEinoStatusOnlyCompletionResult 判断是否只返回了阶段完成声明，却没有用户可见报告。
// 该状态常见于 Supervisor 把 phase_ledger 当成 final_result；它不是合格交付。
func IsEinoStatusOnlyCompletionResult(result *RunResult) bool {
	if result == nil {
		return false
	}
	return isEinoStatusOnlyCompletionText(result.Response)
}

func isEinoStatusOnlyCompletionText(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > 1200 {
		return false
	}
	lower := strings.ToLower(s)
	claimsCompletion := strings.Contains(s, "可以交付") ||
		strings.Contains(s, "无未闭合") ||
		(strings.Contains(s, "阶段") && (strings.Contains(lower, "passed") || strings.Contains(lower, "blocked")))
	if !claimsCompletion {
		return false
	}
	reportMarkers := []string{
		"结论摘要", "风险概览", "覆盖账本", "资产覆盖", "已确认发现",
		"复现证据", "测试结果", "负结果", "范围限制", "修复建议",
	}
	sections := 0
	for _, marker := range reportMarkers {
		if strings.Contains(s, marker) {
			sections++
		}
	}
	return sections < 3
}

// HasEinoResumeTrace 轨迹非空，续跑才有上下文可恢复。
func HasEinoResumeTrace(result *RunResult) bool {
	if result == nil {
		return false
	}
	s := strings.TrimSpace(result.LastAgentTraceInput)
	return s != "" && s != "[]" && s != "null"
}

// EmptyResponseContinueMaxAttemptsFromConfig 无助手正文时 Handler 层退避续跑上限；0=默认 5。
func EmptyResponseContinueMaxAttemptsFromConfig(mw *config.MultiAgentEinoMiddlewareConfig) int {
	if mw != nil && mw.EmptyResponseContinueMaxAttempts > 0 {
		return mw.EmptyResponseContinueMaxAttempts
	}
	return defaultEmptyResponseContinueMaxAttempts
}

// EmptyResponseContinueBackoff 与 run_retry 相同指数退避（2s, 4s, 8s… capped）。
func EmptyResponseContinueBackoff(attempt int, mw *config.MultiAgentEinoMiddlewareConfig) time.Duration {
	maxBackoff := defaultEinoRunRetryMaxBackoff
	if mw != nil && mw.RunRetryMaxBackoffSec > 0 {
		maxBackoff = time.Duration(mw.RunRetryMaxBackoffSec) * time.Second
	}
	return einoTransientRetryBackoff(attempt, maxBackoff)
}

const (
	EinoResponseContinueKindEmpty       = "empty_response"
	EinoResponseContinueKindFinalReport = "final_report"
)

// EinoResponseContinueInstruction 为需要自动续跑的结果选择明确恢复指令。
// preferFinalReport 用于 Supervisor：即使结果为空，也应直接进入最终报告出口，而不是请求阶段性总结。
func EinoResponseContinueInstruction(result *RunResult, preferFinalReport bool) (instruction, kind string) {
	switch {
	case IsEinoStatusOnlyCompletionResult(result):
		return FormatFinalReportContinueUserMessage(), EinoResponseContinueKindFinalReport
	case IsEinoEmptyResponseResult(result) && preferFinalReport:
		return FormatFinalReportContinueUserMessage(), EinoResponseContinueKindFinalReport
	case IsEinoEmptyResponseResult(result):
		return FormatEmptyResponseContinueUserMessage(), EinoResponseContinueKindEmpty
	default:
		return "", ""
	}
}

// FormatEmptyResponseContinueUserMessage 系统自动续跑时注入的 user 轮次（不写入 messages 表气泡）。
func FormatEmptyResponseContinueUserMessage() string {
	return strings.TrimSpace(`【系统自动续跑 / Auto resume】
上一轮 Eino 会话未产出可见助手正文（可能流式中断或仅完成工具调用）。请基于已有轨迹与工具结果继续推进，并给出阶段性总结；勿重复已完成步骤。`)
}

// FormatFinalReportContinueUserMessage 要求协调者从已有证据生成报告，不为凑篇幅重跑扫描。
func FormatFinalReportContinueUserMessage() string {
	return strings.TrimSpace(`【系统交付修复 / Final report required】
上一轮只返回了阶段状态或“可以交付”，没有生成用户要求的正式报告。不要重复已完成的扫描，也不要只再次声明完成。请基于已有轨迹、phase_ledger、项目事实和工具证据，直接输出完整最终报告；全面任务至少包含结论与风险概览、资产/入口覆盖账本、已确认发现及复现证据、适用风险族测试结果、负结果、blocked/gap 和范围限制。Supervisor 必须把报告全文写入 exit.final_result。`)
}
