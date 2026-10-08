package handler

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/projectprompt"
	"cyberstrike-ai/internal/tooloutput"
)

func TestAllCoverageContinuationPathsShareImpactPolicy(t *testing.T) {
	checks := []string{"sensitive candidate still unverified"}
	artifactMessage, _ := coverageContinuationMessage(checks, tooloutput.SpillOpts{RootDir: t.TempDir(), ExecutionID: "policy-checks.json"})
	messages := map[string]string{
		"inline fallback": formatCoverageContinueMessage(checks),
		"artifact":        artifactMessage,
		"stagnation":      classifyAndVerifyContinuationMessage(agentfinalizer.Decision{MissingChecks: checks}),
	}
	for name, message := range messages {
		t.Run(name, func(t *testing.T) {
			if strings.Count(message, projectprompt.HighImpactFindingPolicy) != 1 {
				t.Fatal("continuation must carry the common impact policy exactly once")
			}
			for _, guard := range []string{"不要无选择地遍历 URL", "不补台账", "阶段报告", "exit.final_result", checks[0]} {
				if !strings.Contains(message, guard) {
					t.Errorf("continuation lost %q", guard)
				}
			}
		})
	}
}
