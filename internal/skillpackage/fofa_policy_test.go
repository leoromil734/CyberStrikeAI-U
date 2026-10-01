package skillpackage

import (
	"strings"
	"testing"
)

func TestInitialFOFAPolicyMatchesSkillsRolesAndAgents(t *testing.T) {
	root := bundledSkillsRoot(t)
	for _, name := range []string{"recon-osint-playbook", "attack-surface-recon", "src-hunting", "pentest-scan-quick", "pentest-scan-standard", "pentest-scan-deep"} {
		t.Run(name, func(t *testing.T) {
			_, manifest, body := readBundledSkill(t, root, name)
			if !containsBundledTool(strings.Fields(manifest.AllowedTools), "fofa_search") {
				t.Error("FOFA is mandatory but not declared as an available skill tool")
			}
			for _, phrase := range []string{"实际调用", "fofa_search", "blocked", "本轮"} {
				if !strings.Contains(body, phrase) {
					t.Errorf("initial FOFA policy missing %q", phrase)
				}
			}
		})
	}
	checks := map[string][]string{
		"recon-osint-playbook/references/fofa-first.md":        {"Quick/Standard/Deep", "锁面", "自由跳", "原始查询文本", "成功且零结果", "raw 用本次实际返回", "上游交接已有本轮", "纯离线", "其他来源可补", "not-applicable", "FOFA_API_KEY"},
		"src-hunting/references/rules/dig-scope-workflow.md":   {"0.3 初始信息收集先调用 FOFA", "不主动 FOFA 出圈", "一种子闭环", "上游同目标同范围", "缺 key/配额", "成功零结果"},
		"attack-surface-recon/references/recon-fact-schema.md": {"FOFA 必经来源", "raw按实际返回条目计", "不能N/A替代"},
		"pentest-blackboard/references/coverage-contract.md":   {"所有线上范围都要求", "fofa_search", "not-applicable 不能替代", "单 URL/IP/固定资产清单"},
		"../roles/信息收集.yaml":                                   {"必须先实际调用", "fofa_search", "其他来源不冒充FOFA", "本轮上游有效调用证据可复用"},
		"../roles/渗透测试.yaml":                                   {"先实际调用", "fofa_search", "锁面只查当前host/IP", "离线审阅不新开查询"},
		"../agents/recon.md":                                   {"必须先实际调用", "fofa_search", "不用N/A", "上游本轮同范围有效调用证据可复用"},
		"../agents/intel-collection.md":                        {"必须先实际调用", "fofa_search", "上游本轮同范围有效调用证据可复用"},
	}
	for rel, phrases := range checks {
		body := readBundledDocument(t, root, rel)
		for _, phrase := range phrases {
			if !strings.Contains(body, phrase) {
				t.Errorf("%s missing mandatory FOFA contract %q", rel, phrase)
			}
		}
	}
	role := readBundledDocument(t, root, "../roles/信息收集.yaml")
	for _, obsolete := range []string{"可选测绘 API：fofa", "fofa/zoomeye/quake/shodan（可用则用"} {
		if strings.Contains(role, obsolete) {
			t.Errorf("role retains obsolete optional FOFA policy %q", obsolete)
		}
	}
	method := readBundledDocument(t, root, "src-hunting/references/recon-methodology.md")
	if strings.Contains(method, "备忘，不是开场") || strings.Contains(method, "或外部 MCP `get_alerts`") {
		t.Error("SRC reference contradicts mandatory FOFA kickoff")
	}
}
