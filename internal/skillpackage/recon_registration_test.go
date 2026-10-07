package skillpackage

import (
	"strings"
	"testing"
)

func TestCRTShAndTemporaryMailGuidanceReachEntryPoints(t *testing.T) {
	root := bundledSkillsRoot(t)
	for _, path := range []string{"../roles/信息收集.yaml", "../roles/渗透测试.yaml", "../agents/recon.md", "../agents/intel-collection.md", "../agents/attack-surface-enumeration.md", "../agents/penetration.md"} {
		body := readBundledDocument(t, root, path)
		if !strings.Contains(body, "  - crtsh_search") {
			t.Errorf("%s excludes certificate discovery tool", path)
		}
	}
	for _, name := range []string{"attack-surface-recon", "recon-osint-playbook", "pentest-scan-deep"} {
		_, manifest, body := readBundledSkill(t, root, name)
		if !containsBundledTool(strings.Fields(manifest.AllowedTools), "crtsh_search") {
			t.Errorf("%s omits crt.sh tool declaration", name)
		}
		if !strings.Contains(body, "crtsh_search") {
			t.Errorf("%s omits crt.sh workflow", name)
		}
	}
	for _, path := range []string{"pentest-blackboard/references/results-pipeline.md", "pentest-scan-deep/references/results-pipeline.md", "pentest-verification/references/impact-selection.md", "api-security-testing/references/token-auth.md", "web-attack-methods/references/auth-access.md"} {
		body := readBundledDocument(t, root, path)
		if !strings.Contains(body, "temporary_email") {
			t.Errorf("%s omits controlled mail registration", path)
		}
		for _, obsolete := range []string{"不自动开通邮箱", "不自动补齐受控邮箱和双账号", "仅用户明确要求且范围允许时"} {
			if strings.Contains(body, obsolete) {
				t.Errorf("%s still overrides the configured mailbox workflow: %s", path, obsolete)
			}
		}
	}
}
