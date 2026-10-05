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
		"## 初始信息收集（FOFA 必调）",
		"## 资产、弱口令与 JS 覆盖",
		"## 证据闭环",
		"## 低价值面不测",
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
		"recon/source/{id}/{tool}/{target}",
		"body_fields",
		"scope_kind",
		"raw_output",
		"success≠covered",
		"status、raw、unique、incremental、error、alt_tried",
		"jsluice",
		"recon/endpoint/",
		"不得 record_vulnerability",
		"可执行“下一步”",
		"六类有危害面",
		"有作用的上传",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("comprehensive assessment contract missing %q", required)
		}
	}
	if !strings.Contains(EvidenceLoopSection(), "不能据此跳过新资产、新身份、JS/API") {
		t.Fatal("Do-Not-Repeat scope must not suppress unexplored surfaces")
	}
	if !strings.Contains(EvidenceLoopSection(), "下一条必须验证队首") {
		t.Fatal("evidence loop must verify the candidate queue before another scan")
	}
	if !strings.Contains(SkipLowValueSection(), "不发请求") || !strings.Contains(SkipLowValueSection(), "反射型 XSS") {
		t.Fatal("low-value skip list must tell the agent not to test reflected XSS")
	}
	completion := CompletionContractSection()
	for _, required := range []string{
		"它只是进度更新",
		"不得包装成“后续建议”",
		"最终报告不保留可执行的 high-value tentative/gap",
		"Deep/全面收尾硬闸门",
		"Source Coverage",
		"有作用的上传均有测完",
	} {
		if !strings.Contains(completion, required) {
			t.Errorf("completion contract missing premature-exit guard %q", required)
		}
	}
}

func TestReportSubmissionContractIsScopedToLifecycle(t *testing.T) {
	for _, mode := range []PromptMode{PromptModeDeep, PromptModeSupervisor} {
		prompt := ComposeSystemPrompt("role", mode)
		for _, required := range []string{
			"过程、草稿与报告提交必须区分", "必须实际调用 exit", "报告全文写入 exit.final_result",
			"exit 只是请求结束当前模型执行，不是覆盖证明", "提交不等于覆盖完整", "普通对话可用自然语言回答",
			"子角色的 exit 只结束自身执行", "不得提前终止父任务", "有缺口的阶段报告",
		} {
			if !strings.Contains(prompt, required) {
				t.Errorf("mode %s missing %q", mode, required)
			}
		}
	}
	for _, mode := range []PromptMode{PromptModeSingle, PromptModePlanExecute, PromptModeSubAgent} {
		prompt := ComposeSystemPrompt("role", mode)
		if strings.Contains(prompt, "必须实际调用 exit") || strings.Contains(prompt, "报告全文写入 exit.final_result") {
			t.Errorf("root exit requirement leaked into %s", mode)
		}
	}
	if !strings.Contains(ComposeSystemPrompt("role", PromptModePlanExecute), "保留计划/执行/重规划的原有返回机制") {
		t.Fatal("plan-execute lifecycle changed")
	}
}

func TestSharedContractStaticBudget(t *testing.T) {
	prompt := ComposeSystemPrompt("", PromptModeSingle)
	// 保留既有契约 5600 字符预算；目录覆盖单独限为 600，避免新增规则无界增长。
	const directoryBudget = 600
	if got := utf8.RuneCountInString(DirectoryDiscoverySection()); got > directoryBudget {
		t.Fatalf("directory discovery contract too large: %d runes", got)
	}
	basePrompt := strings.Replace(prompt, "\n\n"+DirectoryDiscoverySection(), "", 1)
	if got := utf8.RuneCountInString(basePrompt); got > 5600 {
		t.Fatalf("existing shared contract too large: %d runes", got)
	}
	if got := utf8.RuneCountInString(prompt); got > 5600+directoryBudget {
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
