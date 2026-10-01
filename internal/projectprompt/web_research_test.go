package projectprompt

import (
	"strings"
	"testing"
)

func TestWebResearchGuidanceReachesEveryAgentMode(t *testing.T) {
	for _, mode := range []PromptMode{PromptModeSingle, PromptModeDeep, PromptModeSupervisor, PromptModePlanExecute, PromptModeSubAgent} {
		prompt := ComposeSystemPrompt("role", mode)
		if strings.Count(prompt, "## 联网检索与按需代理") != 1 {
			t.Errorf("mode %s missing shared research instructions", mode)
		}
		for _, required := range []string{"web_search", "research_plan", "proxy_get", "proxy_release", "401/407", "429降速", "不外传秘密", "不自动执行"} {
			if !strings.Contains(prompt, required) {
				t.Errorf("mode %s missing %q", mode, required)
			}
		}
	}
}
