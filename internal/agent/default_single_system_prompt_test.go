package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	"go.uber.org/zap"
)

func TestDefaultSingleAgentSystemPromptUsesSharedContract(t *testing.T) {
	prompt := DefaultSingleAgentSystemPrompt()
	for _, expected := range []string{
		"单代理安全测试执行者",
		"## 范围与执行边界",
		"## 证据闭环",
		"## 独立安全边界",
		"## 完成与交付",
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("default prompt missing %q", expected)
		}
	}
}

func TestCustomSingleAgentRoleCannotReplaceSharedContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-role.md")
	if err := os.WriteFile(path, []byte("CUSTOM_ROLE_ONLY"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		agentConfig:   &config.AgentConfig{SystemPromptPath: "custom-role.md"},
		promptBaseDir: dir,
		logger:        zap.NewNop(),
	}
	prompt := a.EinoSingleAgentSystemInstruction()
	if !strings.HasPrefix(prompt, "CUSTOM_ROLE_ONLY") {
		t.Fatalf("custom role was not preserved: %q", prompt)
	}
	for _, expected := range []string{"## 范围与执行边界", "## 证据闭环", "## 完成与交付"} {
		if count := strings.Count(prompt, expected); count != 1 {
			t.Fatalf("shared section %q count = %d, want 1", expected, count)
		}
	}
}
