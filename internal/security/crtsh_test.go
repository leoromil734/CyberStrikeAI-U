package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/workspaceguard"
)

func TestCRTShBundledToolHasBoundedArguments(t *testing.T) {
	tool, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", "crtsh_search.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tool.Name != "crtsh_search" || tool.Command != "python3" || !tool.Enabled {
		t.Fatal("crt.sh tool unavailable")
	}
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, tool, map[string]interface{}{"domain": "example.test", "max_retries": 0})
	for flag, value := range map[string]string{"--domain": "example.test", "--timeout-seconds": "60", "--max-retries": "0", "--max-response-bytes": "8388608", "--max-records": "10000"} {
		requireDiscoveryFlag(t, args, flag, value)
	}
	for key, value := range map[string]interface{}{"timeout_seconds": 181, "max_retries": 4, "max_records": 0, "max_response_bytes": 33554433} {
		if err := executor.validateToolParameterValues(tool, map[string]interface{}{"domain": "example.test", key: value}); err == nil {
			t.Errorf("%s accepted unbounded input", key)
		}
	}
	for _, parameter := range tool.Parameters {
		if parameter.Name == "additional_args" || parameter.Name == "api_key" || parameter.Name == "base_url" {
			t.Fatal("unsafe user override exposed")
		}
	}
}

// Opt-in deployment probe: installed script help inside the real namespace,
// without contacting crt.sh or any discovered host.
func TestCRTShDeploymentRuntimeSmoke(t *testing.T) {
	if os.Getenv("CSAI_DEPLOYMENT_SMOKE") != "1" {
		t.Skip("requires installed read-only runtime")
	}
	ctx, _, _ := sandboxFixture(t)
	policy := workspaceguard.FromContext(ctx)
	policy.RuntimeReadOnlyRoots = []string{"/opt/cyberstrike-tool-runtime"}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "/opt/cyberstrike-tool-runtime/scripts/crtsh-recon.py", "--help")
	ConfigureShellCmdForAgentExecute(cmd)
	if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--max-response-bytes") || !strings.Contains(string(out), "--domain") {
		t.Fatalf("sandbox crt.sh runtime failed: %v %s", err, out)
	}
}
