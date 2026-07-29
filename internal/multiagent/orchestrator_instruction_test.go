package multiagent

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/agents"
	"cyberstrike-ai/internal/config"
)

func TestResolveMainOrchestratorInstructionComposesEachMode(t *testing.T) {
	cfg := &config.MultiAgentConfig{
		OrchestratorInstruction:            "DEEP_CUSTOM_ROLE",
		OrchestratorInstructionSupervisor:  "SUPERVISOR_CUSTOM_ROLE",
		OrchestratorInstructionPlanExecute: "PLAN_CUSTOM_ROLE",
	}
	tests := []struct {
		mode       string
		roleMarker string
		lifecycle  string
	}{
		{"deep", "DEEP_CUSTOM_ROLE", "## Deep 生命周期"},
		{"supervisor", "SUPERVISOR_CUSTOM_ROLE", "## Supervisor 生命周期"},
		{"plan_execute", "PLAN_CUSTOM_ROLE", "## Plan-Execute 生命周期"},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			prompt, _ := resolveMainOrchestratorInstruction(tt.mode, cfg, nil)
			if !strings.HasPrefix(prompt, tt.roleMarker) {
				t.Fatalf("mode %s did not preserve its role prompt", tt.mode)
			}
			for _, expected := range []string{tt.lifecycle, "## 范围与执行边界", "## 证据闭环", "## 独立安全边界", "## 完成与交付"} {
				if count := strings.Count(prompt, expected); count != 1 {
					t.Fatalf("section %q count = %d, want 1", expected, count)
				}
			}
		})
	}
}

func TestResolveMainOrchestratorInstructionMarkdownOverridesRoleOnly(t *testing.T) {
	cfg := &config.MultiAgentConfig{OrchestratorInstructionSupervisor: "CONFIG_ROLE"}
	load := &agents.MarkdownDirLoad{
		OrchestratorSupervisor: &agents.OrchestratorMarkdown{Instruction: "MARKDOWN_ROLE"},
	}
	prompt, meta := resolveMainOrchestratorInstruction("supervisor", cfg, load)
	if meta != load.OrchestratorSupervisor {
		t.Fatal("expected supervisor markdown metadata")
	}
	if !strings.HasPrefix(prompt, "MARKDOWN_ROLE") || strings.Contains(prompt, "CONFIG_ROLE") {
		t.Fatalf("unexpected role precedence: %q", prompt)
	}
	if strings.Count(prompt, "## 证据闭环") != 1 {
		t.Fatal("shared contract must still be composed exactly once")
	}
}

func TestDefaultOrchestratorInstructionsUseSharedContract(t *testing.T) {
	prompts := []string{
		DefaultDeepOrchestratorInstruction(),
		DefaultSupervisorOrchestratorInstruction(),
		DefaultPlanExecuteOrchestratorInstruction(),
	}
	for i, prompt := range prompts {
		if strings.Count(prompt, "## 范围与执行边界") != 1 || strings.Count(prompt, "## 证据闭环") != 1 {
			t.Fatalf("default prompt %d does not use shared contract", i)
		}
	}
}
