// Package vulnquality 提供不依赖数据库和传输层的漏洞独立性判定。
package vulnquality

import (
	"fmt"
	"strings"
)

// BoundaryValidation 描述攻击者起始权限与候选漏洞实际跨越的安全边界。
type BoundaryValidation struct {
	AttackerStartingState        string
	CredentialCompromiseRequired bool
	SecurityBoundaryCrossed      string
	AdditionalAuthorityProven    bool
	ControlComparison            string
}

// ParseBoundaryValidation 从 record_vulnerability 参数解析结构化边界证据。
func ParseBoundaryValidation(args map[string]interface{}) (BoundaryValidation, []string) {
	raw, ok := args["validation"].(map[string]interface{})
	if !ok {
		return BoundaryValidation{}, []string{"validation（独立安全边界验证对象）"}
	}

	v := BoundaryValidation{
		AttackerStartingState:        strings.TrimSpace(stringValue(raw, "attacker_starting_state")),
		CredentialCompromiseRequired: boolValue(raw, "credential_compromise_required"),
		SecurityBoundaryCrossed:      strings.TrimSpace(stringValue(raw, "security_boundary_crossed")),
		AdditionalAuthorityProven:    boolValue(raw, "additional_authority_proven"),
		ControlComparison:            strings.TrimSpace(stringValue(raw, "control_comparison")),
	}
	missing := make([]string, 0, 5)
	if v.AttackerStartingState == "" {
		missing = append(missing, "validation.attacker_starting_state（攻击者执行本漏洞前实际拥有的权限）")
	}
	if _, exists := raw["credential_compromise_required"].(bool); !exists {
		missing = append(missing, "validation.credential_compromise_required（是否预设已窃取有效凭据/会话）")
	}
	if v.SecurityBoundaryCrossed == "" {
		missing = append(missing, "validation.security_boundary_crossed（被跨越的独立安全边界）")
	}
	if _, exists := raw["additional_authority_proven"].(bool); !exists {
		missing = append(missing, "validation.additional_authority_proven（是否证明获得起始权限之外的能力）")
	}
	if v.ControlComparison == "" {
		missing = append(missing, "validation.control_comparison（基线与攻击请求的对照证据）")
	}
	return v, missing
}

// ValidateBoundary 拒绝未证明新增权限的候选，尤其是依赖已失陷会话的正常操作。
func ValidateBoundary(v BoundaryValidation) error {
	if v.AdditionalAuthorityProven {
		return nil
	}
	if v.CredentialCompromiseRequired {
		return fmt.Errorf("候选依赖已窃取/接管的有效凭据或会话，但未证明获得该身份正常权限之外的额外能力；这属于已失陷会话的既有权限，不是独立漏洞。请改记 tentative/负结果 fact，或补充跨用户、跨角色、跨租户、未授权操作等对照证据")
	}
	return fmt.Errorf("尚未证明攻击者获得起始权限之外的能力，不能记录为正式漏洞；请补充匿名/低权限基线与攻击结果的可复现差分")
}

// PrependBoundaryEvidence 把门禁输入固化到现有前置条件和证据字段，便于后续审计。
func PrependBoundaryEvidence(v BoundaryValidation, preconditions, evidence string) (string, string) {
	credentialRequired := "否"
	if v.CredentialCompromiseRequired {
		credentialRequired = "是"
	}
	boundaryPreconditions := fmt.Sprintf("攻击者起始状态: %s\n依赖已失陷的有效凭据/会话: %s", v.AttackerStartingState, credentialRequired)
	if strings.TrimSpace(preconditions) != "" {
		boundaryPreconditions += "\n" + preconditions
	}
	boundaryEvidence := fmt.Sprintf("跨越的独立安全边界: %s\n基线/攻击对照: %s", v.SecurityBoundaryCrossed, v.ControlComparison)
	if strings.TrimSpace(evidence) != "" {
		boundaryEvidence += "\n\n" + evidence
	}
	return boundaryPreconditions, boundaryEvidence
}

func stringValue(values map[string]interface{}, key string) string {
	value, _ := values[key].(string)
	return value
}

func boolValue(values map[string]interface{}, key string) bool {
	value, _ := values[key].(bool)
	return value
}
