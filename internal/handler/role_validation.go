package handler

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// validateRoleName rejects names that cannot safely and uniquely identify a
// role configuration file. Existing files are not renamed by this validation.
func validateRoleName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("角色名称不能为空")
	}
	if name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > 64 {
		return fmt.Errorf("角色名称不能包含首尾空格，长度不能超过 64 个字符")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("角色名称不能包含路径或文件名特殊字符")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("角色名称不能包含控制字符")
		}
	}
	return nil
}
