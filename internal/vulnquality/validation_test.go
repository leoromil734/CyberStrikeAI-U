package vulnquality

import (
	"strings"
	"testing"
)

func completeBoundaryValidation(overrides map[string]interface{}) map[string]interface{} {
	validation := map[string]interface{}{
		"attacker_starting_state":        "匿名",
		"credential_compromise_required": false,
		"security_boundary_crossed":      "匿名到已认证",
		"additional_authority_proven":    true,
		"control_comparison":             "不带会话返回 401；相同请求利用缺陷后返回 200",
	}
	for key, value := range overrides {
		validation[key] = value
	}
	return validation
}

func TestBoundaryRejectsCompromisedSessionWithoutNewAuthority(t *testing.T) {
	args := map[string]interface{}{
		"validation": completeBoundaryValidation(map[string]interface{}{
			"attacker_starting_state":        "已窃取用户 A 的有效 session token",
			"credential_compromise_required": true,
			"security_boundary_crossed":      "读取用户 A 自己的 MFA seed",
			"additional_authority_proven":    false,
			"control_comparison":             "同一用户 A 的正常会话调用接口返回相同数据",
		}),
	}
	validation, missing := ParseBoundaryValidation(args)
	if len(missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", missing)
	}
	if err := ValidateBoundary(validation); err == nil || !strings.Contains(err.Error(), "不是独立漏洞") {
		t.Fatalf("expected compromised-session rejection, got %v", err)
	}
}

func TestBoundaryAcceptsAdditionalCrossRoleAuthority(t *testing.T) {
	args := map[string]interface{}{
		"validation": completeBoundaryValidation(map[string]interface{}{
			"attacker_starting_state":        "已窃取普通用户 A 的有效 session token",
			"credential_compromise_required": true,
			"security_boundary_crossed":      "普通用户到管理员",
			"additional_authority_proven":    true,
			"control_comparison":             "普通资源返回 200；仅替换为管理员资源 ID 仍返回管理员密钥",
		}),
	}
	validation, missing := ParseBoundaryValidation(args)
	if len(missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", missing)
	}
	if err := ValidateBoundary(validation); err != nil {
		t.Fatalf("cross-role authority should pass: %v", err)
	}
}

func TestBoundaryRequiresExplicitStructuredEvidence(t *testing.T) {
	_, missing := ParseBoundaryValidation(map[string]interface{}{
		"validation": map[string]interface{}{
			"attacker_starting_state": "普通用户 A",
		},
	})
	joined := strings.Join(missing, "\n")
	for _, field := range []string{
		"credential_compromise_required",
		"security_boundary_crossed",
		"additional_authority_proven",
		"control_comparison",
	} {
		if !strings.Contains(joined, field) {
			t.Fatalf("missing list does not contain %s: %s", field, joined)
		}
	}
}

func TestBoundaryEvidenceIsPersistedWithFinding(t *testing.T) {
	validation := BoundaryValidation{
		AttackerStartingState:        "普通用户 A",
		CredentialCompromiseRequired: false,
		SecurityBoundaryCrossed:      "用户 A 到用户 B",
		AdditionalAuthorityProven:    true,
		ControlComparison:            "对象 A 返回自身资料；只替换 ID 后返回对象 B 资料",
	}
	preconditions, evidence := PrependBoundaryEvidence(validation, "需要普通账号", "HTTP 200 响应包含用户 B 邮箱")
	for _, expected := range []string{"普通用户 A", "依赖已失陷的有效凭据/会话: 否", "需要普通账号"} {
		if !strings.Contains(preconditions, expected) {
			t.Fatalf("preconditions missing %q: %s", expected, preconditions)
		}
	}
	for _, expected := range []string{"用户 A 到用户 B", "只替换 ID", "用户 B 邮箱"} {
		if !strings.Contains(evidence, expected) {
			t.Fatalf("evidence missing %q: %s", expected, evidence)
		}
	}
}
