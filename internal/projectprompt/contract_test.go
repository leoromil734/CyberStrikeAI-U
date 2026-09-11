package projectprompt

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestComposeSystemPromptIncludesSharedContractOnce(t *testing.T) {
	modes := map[string]PromptMode{
		"single":       PromptModeSingle,
		"deep":         PromptModeDeep,
		"supervisor":   PromptModeSupervisor,
		"plan_execute": PromptModePlanExecute,
		"sub_agent":    PromptModeSubAgent,
	}
	required := []string{
		"## 范围与执行边界",
		"## 证据闭环",
		"## 独立安全边界",
		"## 执行与恢复",
		"## Skill 路由",
		"## 全面评估门禁",
		"## 项目黑板与漏洞记录",
		"## 完成与交付",
	}
	for name, mode := range modes {
		t.Run(name, func(t *testing.T) {
			const role = "ROLE_MARKER\n\n只描述角色特有职责。"
			prompt := ComposeSystemPrompt(role, mode)
			if !strings.HasPrefix(prompt, role) {
				t.Fatalf("role instruction must be the first section")
			}
			for _, section := range required {
				if count := strings.Count(prompt, section); count != 1 {
					t.Fatalf("section %q count = %d, want 1", section, count)
				}
			}
			for _, rejected := range []string{"2000+", "$500", "前 0.1%", "隐藏思维链"} {
				if strings.Contains(prompt, rejected) {
					t.Fatalf("prompt contains rejected slogan or reasoning request %q", rejected)
				}
			}
		})
	}
}

func TestComposeSystemPromptModeLifecycleIsDistinct(t *testing.T) {
	tests := []struct {
		mode PromptMode
		want string
	}{
		{PromptModeSingle, "## 单代理生命周期"},
		{PromptModeDeep, "## Deep 生命周期"},
		{PromptModeSupervisor, "## Supervisor 生命周期"},
		{PromptModePlanExecute, "## Plan-Execute 生命周期"},
		{PromptModeSubAgent, "## 子任务生命周期"},
	}
	for _, tt := range tests {
		prompt := ComposeSystemPrompt("role", tt.mode)
		if !strings.Contains(prompt, tt.want) {
			t.Fatalf("mode %q missing lifecycle %q", tt.mode, tt.want)
		}
	}
}

func TestComprehensiveAssessmentContractPreventsPrematureExit(t *testing.T) {
	contract := ComprehensiveAssessmentSection()
	for _, required := range []string{
		"subfinder、oneforall、dnsx",
		"phase_ledger",
		"pending",
		"active",
		"passed",
		"blocked",
		"recon/source/",
		"status、raw、unique、incremental、error、alt_tried",
		"jsluice",
		"recon/endpoint/",
		"不得 record_vulnerability",
		"可执行“下一步”",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("comprehensive assessment contract missing %q", required)
		}
	}
	if !strings.Contains(EvidenceLoopSection(), "不能据此跳过新资产、新身份、JS/API") {
		t.Fatal("Do-Not-Repeat scope must not suppress unexplored surfaces")
	}
	completion := CompletionContractSection()
	for _, required := range []string{
		"它只是进度更新",
		"不得包装成“后续建议”",
		"最终报告不保留可执行的 high-value tentative/gap",
		"Deep/全面收尾硬闸门",
		"Source Coverage",
	} {
		if !strings.Contains(completion, required) {
			t.Errorf("completion contract missing premature-exit guard %q", required)
		}
	}
}

func TestSharedContractStaticBudget(t *testing.T) {
	prompt := ComposeSystemPrompt("", PromptModeSingle)
	if got := utf8.RuneCountInString(prompt); got > 3450 {
		t.Fatalf("shared single-agent contract too large: %d runes", got)
	}
	scope := ScopeAuthorizationSection()
	for _, required := range []string{"发现并验证漏洞", "程度可控", "不得以“非破坏/可逆/最小影响/怕副作用”跳过验证"} {
		if !strings.Contains(scope, required) {
			t.Errorf("scope authorization missing priority policy %q", required)
		}
	}
	if strings.Contains(scope, "非破坏、可逆、最小影响的验证") {
		t.Fatal("scope must not reintroduce non-destructive-only primary policy")
	}
}

func TestConciseBlackboardRequiresRunnablePOC(t *testing.T) {
	section := ConciseBlackboardSection(false, false)
	for _, required := range []string{
		"完整POC脚本+输出",
		"受控写入禁止文件名/省略号",
	} {
		if !strings.Contains(section, required) {
			t.Errorf("blackboard contract missing %q", required)
		}
	}
}

func TestJoinPromptSectionsDropsExactDuplicates(t *testing.T) {
	if got := joinPromptSections("alpha", " beta ", "alpha", ""); got != "alpha\n\nbeta" {
		t.Fatalf("unexpected joined sections: %q", got)
	}
}
