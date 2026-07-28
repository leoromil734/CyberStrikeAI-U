package projectprompt

import (
	"strings"
	"testing"
)

func TestBlackboardPromptsIncludeIndependentBoundaryPolicy(t *testing.T) {
	prompts := map[string]string{
		"builtin":  FactRecordingBlackboardSection(false),
		"markdown": FactRecordingBlackboardSectionMarkdown(true),
	}
	for name, prompt := range prompts {
		t.Run(name, func(t *testing.T) {
			for _, expected := range []string{
				"独立漏洞判定",
				"攻击者起始状态",
				"已失陷凭据不是免费前提",
				"MFA seed",
				"不得用“如果先拿到 token/cookie”补齐影响",
			} {
				if !strings.Contains(prompt, expected) {
					t.Fatalf("prompt missing %q", expected)
				}
			}
		})
	}
}
