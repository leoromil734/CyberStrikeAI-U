package security

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// FormatCommandFailureResult 与 exec 工具 ToolResult 文案一致（不含 ToolErrorPrefix）。
func FormatCommandFailureResult(exitCode int, output string) string {
	output = strings.TrimSpace(output)
	errMsg := fmt.Sprintf("exit status %d", exitCode)
	if output == "" {
		return fmt.Sprintf("命令执行失败: %s", errMsg)
	}
	if strings.HasPrefix(output, "命令执行失败:") {
		return output
	}
	return fmt.Sprintf("命令执行失败: %s\n输出: %s", errMsg, output)
}

// FormatCommandFailureFromErr 根据 exec/execute 返回的 error 生成统一失败文案（IsError 正文）。
func FormatCommandFailureFromErr(err error, output string) string {
	if err == nil {
		return strings.TrimSpace(output)
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return FormatCommandFailureResult(exitError.ExitCode(), output)
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return fmt.Sprintf("命令执行失败: %v", err)
	}
	if strings.HasPrefix(output, "命令执行失败:") {
		return output
	}
	return fmt.Sprintf("命令执行失败: %v\n输出: %s", err, output)
}

// ExecuteFailureStatusLine 流式 execute 结束时追加的单行状态（输出正文已在流中推送过）。
func ExecuteFailureStatusLine(exitCode int) string {
	return fmt.Sprintf("\n命令执行失败: exit status %d", exitCode)
}

// IsCommandFailureResult 判断工具结果正文是否表示命令非零退出（用于 execute / exec 对齐 isError）。
func IsCommandFailureResult(content string) bool {
	return strings.Contains(content, "命令执行失败:")
}

// commandArgumentErrorMarkers 是「命令因参数用法被拒绝」的输出特征。
// 出现这些字样说明命令行本身不合法，而不是目标不可达，模型应当修正参数后重试。
var commandArgumentErrorMarkers = []string{
	"quitting!",                     // nmap：参数解析失败后立即退出
	"must be a positive",            // nmap --min-rate 等取值格式错误
	"unknown flag",                  // 通用
	"unknown option",                //
	"unrecognized option",           //
	"unrecognized argument",         //
	"invalid option",                //
	"invalid argument",              //
	"invalid value",                 //
	"flag provided but not defined", // Go flag 风格
	"expected argument",             //
	"requires an argument",          //
	"missing argument",              //
	"usage:",                        // 参数不合法的同时打印用法
	"参数错误",                          // 中文工具
	"无效参数",                          //
}

// CommandArgumentErrorHint 在命令因参数用法失败时，给模型一句可执行的修正方向。
// 原始报错往往只有一句 usage/QUITTING，模型容易误判成「工具不可用」而绕开它，
// 例如改用 exec 重写命令，从而丢掉工具封装带来的参数校验与默认值。
func CommandArgumentErrorHint(toolName, output string) string {
	lowered := strings.ToLower(output)
	matched := false
	for _, marker := range commandArgumentErrorMarkers {
		if strings.Contains(lowered, marker) {
			matched = true
			break
		}
	}
	if !matched {
		return ""
	}
	return fmt.Sprintf(
		"[参数用法错误] 命令 %s 拒绝了本次参数：请逐个核对每个 --flag 是否紧跟其取值、取值格式是否正确，"+
			"不要在选项与取值之间插入其它选项，修正后用同样的工具重试（必要时才改用 exec 运行等价命令）。",
		toolName,
	)
}

// IsLegacyShellExitNoise 过滤旧版 shell 流中冗余的 exit code 行。
func IsLegacyShellExitNoise(s string) bool {
	trimmed := strings.TrimSpace(s)
	return strings.HasPrefix(trimmed, "command exited with non-zero code ")
}
