package security

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"cyberstrike-ai/internal/workspaceguard"
)

// prepareWorkspaceCommand applies an OS mount/PID/user namespace, not a command
// blacklist. All shell interpreters and subprocesses inherit the same boundary.
// A missing sandbox is an error; it must never fall back to host execution.
func prepareWorkspaceCommand(ctx context.Context, cmd *exec.Cmd, credentialKeys ...string) error {
	p := workspaceguard.FromContext(ctx)
	if p == nil {
		return nil
	} // caller controls whether a trusted run is configured
	if runtime.GOOS != "linux" {
		return fmt.Errorf("isolated local execution requires Linux and bubblewrap")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("local execution blocked: install bubblewrap; unsafe fallback is disabled")
	}
	workdir, err := p.Resolve(cmd.Dir, true)
	if err != nil {
		return err
	}
	if st, err := os.Stat(workdir); err != nil || !st.IsDir() {
		return fmt.Errorf("workspace workdir must be an existing directory")
	}
	if err := workspaceguard.NoSymlink(p.Workspace); err != nil {
		return err
	}
	home, err := workspaceguard.EnsureDir(filepath.Join(p.Workspace, ".home"))
	if err != nil {
		return err
	}
	tmp, err := workspaceguard.EnsureDir(filepath.Join(p.Workspace, ".tmp"))
	if err != nil {
		return err
	}
	args := []string{"--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--cap-drop", "ALL", "--clearenv"}
	// Host root, /root, /var, /run and host /proc are never exposed.
	for _, path := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/ssl", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/ld.so.cache", "/etc/alternatives"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	// Mount private /tmp first so temporary fixture/runtime/workspace paths are
	// not hidden by a later over-mount.
	args = append(args, "--dev", "/dev", "--proc", "/proc", "--bind", tmp, "/tmp")
	for _, path := range p.RuntimeReadOnlyRoots {
		if err := validateRuntimeMount(path); err != nil {
			return err
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("sandbox runtime missing: %s", path)
		}
		args = append(args, "--ro-bind", path, path)
	}
	args = append(args, "--bind", p.Workspace, p.Workspace)
	for _, path := range p.ReadOnlyRoots {
		if err := workspaceguard.NoSymlink(path); err != nil {
			return err
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		args = append(args, "--ro-bind", path, path)
	}
	for _, path := range p.RuntimeWritableRoots {
		allowed := false
		for _, root := range p.RuntimeReadOnlyRoots {
			if path != root && workspaceguard.Within(root, path) {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("writable vendor state must be a subdirectory of a read-only runtime")
		}
		if err := workspaceguard.NoSymlink(path); err != nil {
			return err
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return fmt.Errorf("runtime state directory must already exist: %s", path)
		}
		hash := sha256.Sum256([]byte(path))
		state, err := workspaceguard.EnsureDir(filepath.Join(p.Workspace, ".tool-state", fmt.Sprintf("%x", hash[:8])))
		if err != nil {
			return err
		}
		args = append(args, "--bind", state, path)
	}
	for _, path := range p.DeniedRoots {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--tmpfs", path, "--remount-ro", path)
		}
	}
	// Only this execution's managed artifact directory is writable. The rest of
	// the project's evidence/reduction store stays read-only.
	for _, item := range cmd.Env {
		if !strings.HasPrefix(item, "CSAI_ARTIFACT_DIR=") {
			continue
		}
		path := strings.TrimPrefix(item, "CSAI_ARTIFACT_DIR=")
		allowed := false
		for _, root := range p.ReadOnlyRoots {
			if workspaceguard.Within(root, path) && filepath.Base(filepath.Dir(path)) == "executions" {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("artifact directory is outside the current execution workspace")
		}
		if err := workspaceguard.NoSymlink(path); err != nil {
			return err
		}
		args = append(args, "--bind", path, path)
	}
	args = append(args, "--remount-ro", "/", "--chdir", workdir)
	env := safeWorkspaceEnv(cmd.Env, home, tmp)
	for _, item := range cmd.Env {
		key, _, _ := strings.Cut(item, "=")
		for _, allowed := range credentialKeys {
			if key == allowed {
				env = append(env, item)
			}
		}
	}
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		args = append(args, "--setenv", key, value)
	}
	command := cmd.Path
	if !filepath.IsAbs(command) {
		command, err = exec.LookPath(command)
		if err != nil {
			return err
		}
	}
	identity, err := workspaceIdentity(p, cmd)
	if err != nil {
		return err
	}
	args = append(args, identity...)
	args = append(args, "--", command)
	if len(cmd.Args) > 1 {
		args = append(args, cmd.Args[1:]...)
	}
	cmd.Path = bwrap
	cmd.Args = append([]string{bwrap}, args...)
	cmd.Dir = p.Workspace
	// Do not expose service credentials to the bubblewrap launcher either.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	return nil
}

func validateRuntimeMount(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("runtime mount must be a clean absolute path")
	}
	for _, forbidden := range []string{"/", "/opt", "/root", "/home", "/etc", "/proc", "/sys", "/run", "/var", "/tmp"} {
		if path == forbidden {
			return fmt.Errorf("over-broad sandbox runtime mount rejected: %s", path)
		}
	}
	for _, forbidden := range []string{"/root", "/home", "/etc", "/proc", "/sys", "/run", "/var"} {
		if workspaceguard.Within(forbidden, path) {
			return fmt.Errorf("private host state cannot be a runtime mount: %s", path)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if workspaceguard.Within(path, cwd) || (workspaceguard.Within(cwd, path) && path != filepath.Join(cwd, "venv")) {
		return fmt.Errorf("application source/configuration cannot be mounted into tool execution")
	}
	return workspaceguard.NoSymlink(path)
}

func safeWorkspaceEnv(env []string, home, tmp string) []string {
	out := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "CSAI_WORKSPACE_SANDBOX=1", "HOME=" + home, "TMPDIR=" + tmp, "TMP=" + tmp, "TEMP=" + tmp, "XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "XDG_CONFIG_HOME=" + filepath.Join(home, ".config")}
	// Credential-backed named tools inject their credential after sandboxing.
	// Arbitrary exec/execute/Python never inherit API/database/cloud credentials.
	for _, item := range env {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		switch key {
		case "TERM", "COLUMNS", "LINES", "PAGER", "GIT_PAGER", "MANPAGER", "NO_COLOR", "CSAI_EXECUTION_ID", "CSAI_ARTIFACT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy":
			out = append(out, item)
		}
	}
	return out
}
