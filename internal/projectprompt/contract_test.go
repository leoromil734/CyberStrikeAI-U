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

func TestSharedContractStaticBudget(t *testing.T) {
	prompt := ComposeSystemPrompt("", PromptModeSingle)
	if got := utf8.RuneCountInString(prompt); got > 3200 {
		t.Fatalf("shared single-agent contract too large: %d runes", got)
	}
}

func TestJoinPromptSectionsDropsExactDuplicates(t *testing.T) {
	if got := joinPromptSections("alpha", " beta ", "alpha", ""); got != "alpha\n\nbeta" {
		t.Fatalf("unexpected joined sections: %q", got)
	}
}
