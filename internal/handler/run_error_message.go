package handler

import (
	"strings"

	"cyberstrike-ai/internal/multiagent"
)

// runExecutionErrorMessage 统一运行失败提示文案。
// 模型/上游瞬时故障（可重试）与本地确定性执行失败分开表述，避免用户把「上游抖动」误当成任务结论，
// 也便于一眼看出该重发还是该排查工具。
func runExecutionErrorMessage(runErr error) string {
	if runErr == nil {
		return "执行失败: 未知错误"
	}
	errText := strings.TrimSpace(runErr.Error())
	if errText == "" {
		errText = "未知错误"
	}
	if multiagent.IsModelInterruptError(runErr) {
		return "模型/上游接口暂时不可用（已按策略自动重试仍未成功，可稍后重发或更换 AI 通道）: " + errText
	}
	return "执行失败: " + errText
}
