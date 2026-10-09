package security

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/workspaceguard"
)

func TestWorkspaceCommandGemRuntimeMountValidation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux runtime mount paths; /var is not an absolute Windows path")
	}
	for _, path := range []string{"/var/lib/gems", "/var/lib/gems/3.0.0", "/var/lib/gems/3.0.0/specifications"} {
		t.Run("allowed"+path, func(t *testing.T) {
			if err := validateRuntimeMount(path); err != nil {
				t.Fatalf("explicit gem runtime rejected: %v", err)
			}
		})
	}
	for _, path := range []string{
		"/", "/var", "/var/lib", "/var/lib/gems-private", "/var/lib/gems2", "/var/lib/gem", "/var/lib/Gems",
		"/var/lib/postgresql", "/var/lib/redis", "/var/lib/dpkg", "/var/cache", "/var/log", "/var/tmp",
		"/opt", "/root", "/root/.gem", "/home", "/home/user/.gem", "/etc", "/etc/shadow", "/proc", "/proc/1", "/sys", "/sys/kernel", "/run", "/run/secrets", "/tmp",
	} {
		t.Run("private"+path, func(t *testing.T) {
			err := validateRuntimeMount(path)
			if err == nil || (!strings.Contains(err.Error(), "over-broad") && !strings.Contains(err.Error(), "private host state")) {
				t.Fatalf("private or broad runtime mount must be rejected: %q: %v", path, err)
			}
		})
	}
	// Do not normalize these inputs before validation: even paths that would
	// resolve inside the allowed gem tree must fail closed when unclean.
	for _, path := range []string{
		"/var/lib/gems/", "/var/lib/gems/.", "/var/lib/gems//3.0.0", "/var//lib/gems",
		"/var/lib/gems/../gems/3.0.0", "/var/lib/gems/../postgresql", "/var/lib/gems/3.0.0/../../redis",
	} {
		t.Run("unclean"+path, func(t *testing.T) {
			err := validateRuntimeMount(path)
			if err == nil || !strings.Contains(err.Error(), "clean absolute path") {
				t.Fatalf("unclean runtime mount must be rejected: %q: %v", path, err)
			}
		})
	}
}

func TestWorkspaceCommandRuntimeMountPathValidation(t *testing.T) {
	dir := t.TempDir()
	if err := validateRuntimeMount(dir); err != nil {
		t.Fatalf("narrow runtime fixture rejected: %v", err)
	}
	invalid := []string{"", "var/lib/gems", dir + string(filepath.Separator) + ".", dir + string(filepath.Separator)}
	if runtime.GOOS == "windows" {
		// The Linux-only exception must not accept volume-less Windows paths.
		invalid = append(invalid, "/var/lib/gems", "/var/lib/gems/3.0.0")
	}
	for _, path := range invalid {
		if err := validateRuntimeMount(path); err == nil || !strings.Contains(err.Error(), "clean absolute path") {
			t.Errorf("invalid runtime path accepted: %q: %v", path, err)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{cwd, filepath.Join(cwd, "private-config")} {
		if err := validateRuntimeMount(path); err == nil {
			t.Errorf("application source/configuration runtime accepted: %q", path)
		}
	}
}

func TestWorkspaceCommandRuntimeMountRejectsSymlinks(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real-gems")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "gems")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("creating symlinks requires Windows privileges: %v", err)
		}
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(link, "3.0.0"), filepath.Join(link, "3.0.0", "specifications")} {
		if err := validateRuntimeMount(path); err == nil || !strings.Contains(err.Error(), "symbolic links") {
			t.Errorf("symlink runtime path or ancestor must be rejected: %q: %v", path, err)
		}
	}
}

func TestWorkspaceCommandDoesNotInheritRubyEnvironment(t *testing.T) {
	home := t.TempDir()
	env := safeWorkspaceEnv([]string{
		"GEM_PATH=/root/.gem", "GEM_HOME=/root/.gem", "RUBYOPT=-r/root/private.rb", "BUNDLE_GEMFILE=/root/Gemfile",
	}, home, filepath.Join(home, "tmp"))
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		switch key {
		case "GEM_PATH", "GEM_HOME", "RUBYOPT", "BUNDLE_GEMFILE":
			t.Errorf("private Ruby environment leaked into sandbox: %q", key)
		}
	}
}

func TestWorkspaceCommandNonLinuxFailsClosed(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux execution boundary")
	}
	ctx := workspaceguard.WithPolicy(context.Background(), &workspaceguard.Policy{Workspace: t.TempDir(), RuntimeReadOnlyRoots: []string{"/var/lib/gems/3.0.0"}})
	cmd := &exec.Cmd{Path: "/bin/sh", Args: []string{"/bin/sh", "-c", "true"}}
	if err := prepareWorkspaceCommand(ctx, cmd); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("gem runtime exception allowed an unsafe non-Linux fallback: %v", err)
	}
}

func workspaceCommandRuntimeFixture(t *testing.T) (context.Context, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux namespace integration test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	ws := t.TempDir()
	return workspaceguard.WithPolicy(context.Background(), &workspaceguard.Policy{Workspace: ws}), ws
}

func TestWorkspaceCommandRuntimeWritableStateIsWorkspaceBacked(t *testing.T) {
	ctx, ws := workspaceCommandRuntimeFixture(t)
	// Use a temporary installation rather than modifying the host gem tree.
	gems := filepath.Join(t.TempDir(), "gems")
	state := filepath.Join(gems, "cache")
	if err := os.MkdirAll(state, 0755); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(gems, "shared.gemspec")
	if err := os.WriteFile(shared, []byte("SHARED_GEM"), 0666); err != nil {
		t.Fatal(err)
	}
	// Make writes otherwise possible so the test checks mount isolation, not
	// just ordinary Unix permissions after the sandbox drops privileges.
	for _, path := range []string{gems, state, shared} {
		if err := os.Chmod(path, 0777); err != nil {
			t.Fatal(err)
		}
	}
	p := workspaceguard.FromContext(ctx)
	p.RuntimeReadOnlyRoots = []string{gems}
	for _, path := range []string{gems, filepath.Dir(gems), gems + "-private"} {
		p.RuntimeWritableRoots = []string{path}
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "true")
		if err := prepareWorkspaceCommand(ctx, cmd); err == nil || !strings.Contains(err.Error(), "subdirectory of a read-only runtime") {
			t.Fatalf("writable runtime must be a strict descendant: %q: %v", path, err)
		}
	}
	p.RuntimeWritableRoots = []string{state}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `set -eu; test "$(cat "$1/shared.gemspec")" = SHARED_GEM; ! printf modified > "$1/shared.gemspec"; ! touch "$1/new-gem"; printf private > "$2/new-cache"; echo readonly-ok`, "_", gems, state)
	if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "readonly-ok") {
		t.Fatalf("runtime write isolation failed: %v %s", err, out)
	}
	if got, err := os.ReadFile(shared); err != nil || string(got) != "SHARED_GEM" {
		t.Fatalf("shared gem installation changed: %q %v", got, err)
	}
	for _, path := range []string{filepath.Join(gems, "new-gem"), filepath.Join(state, "new-cache")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("sandbox wrote into shared runtime: %q: %v", path, err)
		}
	}
	paths, err := filepath.Glob(filepath.Join(ws, ".tool-state", "*", "new-cache"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("writable runtime state is not workspace-backed: %v %v", paths, err)
	}
}

func TestWorkspaceCommandWPScanVersionSmoke(t *testing.T) {
	if os.Getenv("CSAI_DEPLOYMENT_SMOKE") != "1" {
		t.Skip("requires opt-in and the Ubuntu Ruby 3.0 WPScan installation")
	}
	ctx, _ := workspaceCommandRuntimeFixture(t)
	const gems = "/var/lib/gems/3.0.0"
	const wpscan = "/usr/local/bin/wpscan"
	if info, err := os.Stat(gems); err != nil || !info.IsDir() {
		t.Skip("Ruby 3.0 gem directory not installed")
	}
	if _, err := os.Stat(wpscan); err != nil {
		t.Skip("WPScan not installed in /usr/local/bin")
	}
	p := workspaceguard.FromContext(ctx)
	p.RuntimeReadOnlyRoots = []string{gems}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wpscan, "--version")
	if err := prepareWorkspaceCommand(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	// Disable networking even if the installed WPScan attempts to contact a
	// service. This probe supplies no target, GEM_PATH or writable gem mount.
	cmd.Args = append([]string{cmd.Args[0], "--unshare-net"}, cmd.Args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Fatalf("offline WPScan --version failed: %v %s", err, out)
	}
}
