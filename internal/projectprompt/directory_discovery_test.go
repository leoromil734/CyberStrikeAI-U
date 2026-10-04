package projectprompt

import (
	"strings"
	"testing"
)

func TestDirectoryDiscoveryPolicyInAllPromptModes(t *testing.T) {
	section := DirectoryDiscoverySection()
	for _, mode := range []PromptMode{PromptModeSingle, PromptModeDeep, PromptModeSupervisor, PromptModePlanExecute, PromptModeSubAgent} {
		t.Run(string(mode), func(t *testing.T) {
			if got := strings.Count(ComposeSystemPrompt("custom role", mode), section); got != 1 {
				t.Fatalf("directory discovery policy count = %d, want 1", got)
			}
		})
	}
}

func TestDirectoryDiscoveryPolicyRequiresCoverageNotToolCounts(t *testing.T) {
	for _, required := range []string{
		"仅任务包含 Web 攻击面发现时", "未链接路径尚未覆盖", "发现需要继续枚举的目录",
		"离线审阅、单接口验证不扩扫", "目录、文件和扩展名枚举优先 dirsearch",
		"参数、虚拟主机和自定义请求模糊测试优先 ffuf", "等价方法", "角色工具范围",
		"相同 origin/路径范围/认证态/字典与扩展名", "充分且仍有效", "可复用", "引用执行记录",
		"不为工具调用次数重复扫描", "catch-all", "并发、速率、请求/总时限及递归深度",
		"用户更严预算优先", "429/持续挑战/健康异常停止该轮", "仅爬取/JS 提取不等于目录覆盖",
		"统一页不能批量否定真实接口", "停止原因和执行/原件引用", "完成所选候选集才 covered",
		"超时/限流/中断未完成留 gap/blocked", "N/A 须范围或能力证据",
		"先验证已有就绪候选", "未完成不宣称全覆盖",
	} {
		if !strings.Contains(DirectoryDiscoverySection(), required) {
			t.Errorf("directory discovery policy missing %q", required)
		}
	}
}
