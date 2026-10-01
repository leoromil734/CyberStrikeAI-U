package vulnquality

import "strings"

// A success assertion is a conclusion, not captured stdout. This narrow check
// leaves arbitrary concrete output formats intact and never verifies or executes
// the submitted PoC.
func descriptiveOnlyPOCOutput(text string) bool {
	text = strings.ToLower(strings.Trim(strings.TrimSpace(text), "。.!！ \t\r\n"))
	switch text {
	case "成功", "执行成功", "验证成功", "利用成功", "脚本执行成功",
		"存在漏洞", "漏洞存在", "已确认漏洞存在", "已验证存在漏洞",
		"脚本执行成功，已经验证漏洞存在且取得预期结果",
		"success", "successful", "execution successful", "vulnerability confirmed", "vulnerable":
		return true
	default:
		return false
	}
}
