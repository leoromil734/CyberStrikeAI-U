package security

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/workspaceguard"
	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/google/uuid"
)

func sandboxFixture(t *testing.T) (context.Context, string, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux namespace integration test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(secret, []byte("CANARY_PLATFORM_SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := workspaceguard.WithPolicy(context.Background(), &workspaceguard.Policy{Workspace: workspace})
	return ctx, workspace, secret
}

func TestWorkspaceCommandNamespace(t *testing.T) {
	ctx, ws, secret := sandboxFixture(t)
	t.Setenv("OPENAI_API_KEY", "CANARY_INHERITED_SECRET")
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `set -eu; pwd; printf safe > local.txt; printf temp > "$TMPDIR/test.txt"; test -z "${OPENAI_API_KEY:-}"; test ! -e "$1"; test ! -e /proc/1/root/opt/CyberStrikeAI-U/config.yaml; ! printf nope > /outside.txt; echo boundary-ok`, "_", secret)
	ConfigureShellCmdForAgentExecute(cmd)
	if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "boundary-ok") || !strings.Contains(string(out), ws) {
		t.Fatalf("sandbox failed: %v %s", err, out)
	}
	for _, path := range []string{filepath.Join(ws, "local.txt"), filepath.Join(ws, ".tmp", "test.txt")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkspaceCommandBlocksEscapesAndPython(t *testing.T) {
	ctx, ws, secret := sandboxFixture(t)
	if err := os.Symlink(secret, filepath.Join(ws, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`cat "$1"`, `cat escape`, `cat ../config.yaml`,
		`python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())' "$1"`,
		`printf bad > /opt/CyberStrikeAI-U/config.yaml`,
	} {
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command, "_", secret)
		if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		out, err := cmd.CombinedOutput()
		if err == nil || strings.Contains(string(out), "CANARY_PLATFORM_SECRET") {
			t.Fatalf("escaped: %s: %s %v", command, out, err)
		}
	}
	got, _ := os.ReadFile(secret)
	if string(got) != "CANARY_PLATFORM_SECRET" {
		t.Fatal("host secret was changed")
	}
}

func TestWorkspaceRejectsOutsideWorkdir(t *testing.T) {
	ctx, _, secret := sandboxFixture(t)
	cmd := exec.Command("/bin/sh", "-c", "true")
	cmd.Dir = filepath.Dir(secret)
	if err := prepareWorkspaceCommand(ctx, cmd); err == nil {
		t.Fatal("external workdir accepted")
	}
}

func TestWorkspaceExecutorAndNativeExecute(t *testing.T) {
	ctx, ws, secret := sandboxFixture(t)
	e, _ := setupTestExecutor(t)
	result, err := e.ExecuteTool(ctx, "exec", map[string]interface{}{"command": "pwd; echo ok > exec.txt"})
	if err != nil || result.IsError {
		t.Fatalf("exec: %v %+v", err, result)
	}
	result, err = e.ExecuteTool(ctx, "exec", map[string]interface{}{"command": "cat " + secret})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("exec read platform secret")
	}
	result, err = e.ExecuteTool(ctx, "exec", map[string]interface{}{"command": "echo unsafe &"})
	if err != nil || !result.IsError {
		t.Fatal("untracked background exec accepted")
	}
	id := uuid.NewString()
	reduction := filepath.Join(t.TempDir(), "reduction")
	p := workspaceguard.FromContext(ctx)
	p.ReadOnlyRoots = []string{filepath.Join(reduction, "conversations", "fixture")}
	p.EvidenceRoot = p.ReadOnlyRoots[0]
	ctx = mcp.WithMCPConversationID(ctx, "fixture")
	ctx = mcp.WithMCPExecutionID(ctx, id)
	ctx = mcp.WithLocalExecutionRuntime(ctx, mcp.LocalExecutionRuntime{SpillRoot: reduction})
	sr, err := NewEinoStreamingShell().ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: "pwd; echo native > native.txt"})
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	for {
		_, err = sr.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"exec.txt", "native.txt"} {
		if _, err := os.Stat(filepath.Join(ws, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkspaceNamedToolRunsInSandbox(t *testing.T) {
	ctx, ws, secret := sandboxFixture(t)
	e, _ := setupTestExecutor(t)
	e.config.Tools = []config.ToolConfig{{Name: "fixture", Command: "/bin/sh", Args: []string{"-c", "test ! -e '" + secret + "'; echo ok > named.txt"}, Enabled: true}}
	e.buildToolIndex()
	result, err := e.ExecuteTool(ctx, "fixture", nil)
	if err != nil || result.IsError {
		t.Fatalf("named tool: %v %+v", err, result)
	}
	if _, err := os.Stat(filepath.Join(ws, "named.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceEnvironmentDoesNotInheritCredentials(t *testing.T) {
	env := safeWorkspaceEnv([]string{"OPENAI_API_KEY=secret", "FOFA_API_KEY=secret", "PGPASSWORD=secret", "LD_PRELOAD=/evil", "CSAI_EXECUTION_ID=fixture"}, "/ws/.home", "/ws/.tmp")
	text := strings.Join(env, "\n")
	if strings.Contains(text, "secret") || strings.Contains(text, "LD_PRELOAD") {
		t.Fatal("credential leakage")
	}
	if !strings.Contains(text, "CSAI_EXECUTION_ID=fixture") {
		t.Fatal("execution metadata lost")
	}
}
