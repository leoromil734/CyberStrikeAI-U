//go:build linux

package security

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"cyberstrike-ai/internal/workspaceguard"
)

// Root services must drop to a real non-root host identity before bubblewrap,
// not merely map host root to a different guest UID (which bypasses NPROC).
func workspaceIdentity(p *workspaceguard.Policy, cmd *exec.Cmd) ([]string, error) {
	uid, gid := os.Geteuid(), os.Getegid()
	if uid != 0 {
		return []string{"--unshare-user", "--uid", strconv.Itoa(uid), "--gid", strconv.Itoa(gid)}, nil
	}
	uid, gid = 65534, 65534
	for _, path := range []string{p.Workspace, p.EvidenceRoot} {
		if path == "" {
			continue
		}
		if err := workspaceguard.NoSymlink(path); err != nil {
			return nil, err
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := grantWorkspaceTraversal(path, uid); err != nil {
			return nil, err
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			return nil, err
		}
		err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := root.Lstat(filepath.FromSlash(name))
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return fmt.Errorf("workspace contains a non-regular entry")
			}
			// Do not transfer ownership of an outside inode via a pre-existing hardlink.
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				if info.Mode().IsRegular() && st.Nlink > 1 {
					return fmt.Errorf("workspace contains a hard-linked file")
				}
				if int(st.Uid) == uid && int(st.Gid) == gid {
					return nil
				}
			}
			// os.Root bounds symlink resolution even if the entry changes after Lstat.
			return root.Lchown(filepath.FromSlash(name), uid, gid)
		})
		root.Close()
		if err != nil {
			return nil, err
		}
	}
	for _, path := range append(append([]string(nil), p.ReadOnlyRoots...), p.RuntimeReadOnlyRoots...) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if err := grantWorkspaceTraversal(path, uid); err != nil {
			return nil, err
		}
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}
	return []string{"--unshare-user", "--uid", strconv.Itoa(uid), "--gid", strconv.Itoa(gid)}, nil
}

// Grant only traversal of managed directories' ancestors. This never grants
// directory listing or file reads and does not chmod shared platform files.
func grantWorkspaceTraversal(path string, uid int) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		st, _ := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm()&0001 == 0 && (st == nil || int(st.Uid) != uid) {
			acl, err := exec.LookPath("setfacl")
			if err != nil {
				return fmt.Errorf("root sandbox setup requires the acl package; unsafe fallback disabled")
			}
			command := exec.Command(acl, "-m", fmt.Sprintf("u:%d:--x", uid), "--", parent)
			command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
			if out, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("workspace traversal ACL: %w: %s", err, out)
			}
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return nil
}
