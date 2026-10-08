package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/workspaceguard"

	"github.com/google/uuid"
)

// Opt-in deployment smoke test for the managed BBOT launcher. It runs inside
// the real bubblewrap policy but only loads modules (--dry-run): no target is
// contacted and no scan is executed.
func TestBBOTDeploymentSandboxSmoke(t *testing.T) {
	if os.Getenv("CSAI_DEPLOYMENT_SMOKE") != "1" {
		t.Skip("requires deployment BBOT installation")
	}
	ctx, workspace, _ := sandboxFixture(t)
	p := workspaceguard.FromContext(ctx)
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	execution := uuid.NewString()
	artifact := filepath.Join(base, "executions", execution)
	if err := os.MkdirAll(artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	// The evidence tree is chowned into the sandbox identity; the runtime roots
	// are mounted read-only exactly as production config does.
	p.ReadOnlyRoots = []string{base}
	p.EvidenceRoot = base
	p.RuntimeReadOnlyRoots = []string{"/opt/cyberstrike-tool-runtime", "/opt/pipx", "/opt/bbot-home"}

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "/usr/local/bin/csai-bbot", args...)
		cmd.Env = append(
			os.Environ(),
			"CSAI_WORKSPACE_SANDBOX=1",
			"CSAI_EXECUTION_ID="+execution,
			"CSAI_ARTIFACT_DIR="+artifact,
		)
		ConfigureShellCmdForAgentExecute(cmd)
		if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("csai-bbot %v failed: %v\n%s", args, err, out)
		}
		return string(out)
	}

	if out := run("--check-runtime"); !strings.Contains(out, "runtime ok") {
		t.Fatalf("runtime check did not report readiness:\n%s", out)
	}
	if out := run("-t", "example.com", "-p", "subdomain-enum", "--dry-run"); !strings.Contains(out, "Setup succeeded for") {
		t.Fatalf("dry run did not load modules:\n%s", out)
	} else if strings.Contains(out, "Read-only file system") {
		t.Fatalf("sandbox run tried to modify the prepared runtime:\n%s", out)
	}

	tools := filepath.Join(workspace, ".home", ".bbot", "tools")
	if info, err := os.Lstat(tools); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("managed bbot home must seed a writable tools directory: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(artifact, "bbot-out")); err != nil {
		t.Fatalf("scan output directory must live in the execution artifacts: %v", err)
	}
}
