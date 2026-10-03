package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/workspaceguard"
)

func TestWorkspaceRuntimeStateAndLegacyDataArePrivate(t *testing.T) {
	ctx, ws, _ := sandboxFixture(t)
	vendor := filepath.Join(t.TempDir(), "vendor")
	state := filepath.Join(vendor, "results")
	skills := filepath.Join(t.TempDir(), "skills")
	private := filepath.Join(skills, ".eino")
	for _, path := range []string{state, private} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "old-result"), []byte("OTHER_PROJECT"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "old-plan"), []byte("OTHER_PROJECT"), 0600); err != nil {
		t.Fatal(err)
	}
	p := workspaceguard.FromContext(ctx)
	p.RuntimeReadOnlyRoots = []string{vendor}
	p.RuntimeWritableRoots = []string{state}
	p.ReadOnlyRoots = []string{skills}
	p.DeniedRoots = []string{private}
	cmd := exec.Command("/bin/sh", "-c", `set -eu; test ! -e "$1/old-result"; test ! -e "$2/old-plan"; echo private > "$1/new-result"; ! echo bad > "$2/file"; echo isolation-ok`, "_", state, private)
	if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "isolation-ok") {
		t.Fatalf("runtime: %s %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(state, "new-result")); !os.IsNotExist(err) {
		t.Fatal("wrote into host vendor results")
	}
	paths, err := filepath.Glob(filepath.Join(ws, ".tool-state", "*", "new-result"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("vendor output is not workspace-backed: %v %v", paths, err)
	}
}

func TestWorkspaceBubblewrapMissingFailsClosed(t *testing.T) {
	ctx, _, _ := sandboxFixture(t)
	cmd := exec.Command("/bin/sh", "-c", "true")
	t.Setenv("PATH", t.TempDir())
	if err := prepareWorkspaceCommand(ctx, cmd); err == nil {
		t.Fatal("fell back to unsandboxed execution")
	}
}
