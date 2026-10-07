package skillpackage

import (
	"strings"
	"testing"
)

func TestHighImpactSelectionAcrossRoleAndSkillEntrypoints(t *testing.T) {
	root := bundledSkillsRoot(t)
	for _, rel := range []string{
		"../agents/penetration.md", "../roles/渗透测试.yaml", "../roles/API安全测试.yaml",
		"pentest-scan-deep/SKILL.md", "api-security-testing/SKILL.md",
		"web-attack-methods/references/auth-access.md", "api-security-testing/references/token-auth.md",
		"src-hunting/references/rules/src-value-hunting.md",
	} {
		t.Run(rel, func(t *testing.T) {
			body := readBundledDocument(t, root, rel)
			for _, marker := range []string{"impact-selection.md", "敏感读或关键写", "temporary_email", "付费文章"} {
				if !strings.Contains(body, marker) {
					t.Errorf("entrypoint lost high-impact selection guard %q", marker)
				}
			}
		})
	}
	guide := readBundledDocument(t, root, "pentest-verification/references/impact-selection.md")
	for _, required := range []string{
		"命令执行", "SQL 注入", "手机号", "用户提供的受控账号与授权凭据",
		"解压或提取内容", "公开联系电话、示例号码", "未解析、解析失败", "tentative/blocked",
		"付费文章全文", "数据库主机名或用户名", "具体可核查的升级或利用链线索",
		"同根因、同安全边界", "不按名称或模型自报的 high/critical",
	} {
		if !strings.Contains(guide, required) {
			t.Errorf("verification guide missing %q", required)
		}
	}
	value := readBundledDocument(t, root, "src-hunting/references/rules/src-value-hunting.md")
	if strings.Contains(value, "只测能出手机号、证件或正文的") {
		t.Fatal("generic article body must not imply sensitive information")
	}
}
