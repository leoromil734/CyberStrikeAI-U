package handler

import (
	"strings"
	"testing"
)

func TestValidateRoleNameSecurity(t *testing.T) {
	for _, name := range []string{"默认", "安全审查员", "read-only", "Role With Spaces", "role_v2", strings.Repeat("中", 64)} {
		if err := validateRoleName(name); err != nil {
			t.Errorf("valid name %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"", " ", " leading", "trailing ", "../role", "a/b", `a\b`, "a..b", "a:b", "a*b", "a?b", `a"b`, "a<b", "a>b", "a|b", "a\x00b", "a\nb", strings.Repeat("中", 65)} {
		if err := validateRoleName(name); err == nil {
			t.Errorf("unsafe name %q accepted", name)
		}
	}
}
