package security

import (
	"os"
	"os/exec"
	"testing"

	"cyberstrike-ai/internal/workspaceguard"
)

// Explicit opt-in: this checks installed programs using help/runtime inspection,
// never a target, provider API or a real scanner invocation.
func TestWorkspaceDeploymentRuntimeSmoke(t *testing.T) {
	if os.Getenv("CSAI_DEPLOYMENT_SMOKE") != "1" {
		t.Skip("requires deployment tool installations")
	}
	ctx, _, _ := sandboxFixture(t)
	p := workspaceguard.FromContext(ctx)
	p.RuntimeReadOnlyRoots = []string{"/opt/cyberstrike-tool-runtime", "/opt/jsapiscan/releases", "/opt/OneForAll", "/opt/pipx", "/opt/wordlists", "/opt/CyberStrikeAI-U/venv"}
	p.RuntimeWritableRoots = []string{"/opt/OneForAll/results"}
	for name, args := range map[string][]string{
		"jsapi_namespace_probe": {"/usr/bin/python3", "-c", "import sys; sys.path.insert(0,'/opt/cyberstrike-tool-runtime/scripts/recon'); import jsapiscan_runner as r; assert r._workspace_sandbox(); root=r._workspace_run_root(); root.mkdir(parents=True,exist_ok=True); print('verified nonroot namespace and private artifacts')"},
		"oneforall_help":        {"/usr/local/bin/oneforall", "--help"},
		"dns_script_help":       {"/opt/CyberStrikeAI-U/venv/bin/python3", "/opt/cyberstrike-tool-runtime/scripts/recon/dns_enum.py", "--help"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, args[0], args[1:]...)
			ConfigureShellCmdForAgentExecute(cmd)
			if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
				t.Fatal(err)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("offline runtime probe failed: %v %s", err, out)
			}
		})
	}
}
