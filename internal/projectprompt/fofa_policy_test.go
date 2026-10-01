package projectprompt

import (
	"strings"
	"testing"
)

func TestInitialFOFAPolicyIsInjectedBeforeEvidenceLoopInEveryMode(t *testing.T) {
	for _, mode := range []PromptMode{PromptModeSingle, PromptModeDeep, PromptModeSupervisor, PromptModePlanExecute, PromptModeSubAgent} {
		t.Run(string(mode), func(t *testing.T) {
			prompt := ComposeSystemPrompt("ROLE", mode)
			first := strings.Index(prompt, "## 初始信息收集（FOFA 必调）")
			loop := strings.Index(prompt, "## 证据闭环")
			if first < 0 || loop < first {
				t.Fatal("FOFA initial policy must precede the evidence loop")
			}
			for _, phrase := range []string{"先实际调用 fofa_search", "Quick/Standard/Deep", "锁面只查当前host/IP", "自由跳只查当前一种子", "上游本轮同范围真实证据可复用", "成功零结果", "其他引擎不冒充FOFA", "未调用不写covered", "不打印密钥", "离线源码/制品审阅"} {
				if !strings.Contains(prompt, phrase) {
					t.Errorf("shared policy missing %q", phrase)
				}
			}
		})
	}
}
