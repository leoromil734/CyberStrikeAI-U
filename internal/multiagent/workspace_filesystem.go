package multiagent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/workspaceguard"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk/filesystem"
)

// workspaceFilesystem is exclusively for model-facing tools. The trusted Local
// used by skill/reduction middleware is deliberately neither embedded nor called:
// even a future Local method must not accidentally expose an unrestricted shell.
// Policy identity binds the backend to one run; its immutable snapshot prevents
// later mutation or a different invocation context from widening that boundary.
type workspaceFilesystem struct {
	source *workspaceguard.Policy
	policy workspaceguard.Policy
}

var _ filesystem.Backend = (*workspaceFilesystem)(nil)

func wrapModelFilesystem(ctx context.Context, _ *localbk.Local) filesystem.Backend {
	return newWorkspaceFilesystem(ctx)
}

func newWorkspaceFilesystem(ctx context.Context) *workspaceFilesystem {
	b := &workspaceFilesystem{source: workspaceguard.FromContext(ctx)}
	if b.source != nil {
		b.policy.Workspace = b.source.Workspace
		b.policy.ReadOnlyRoots = append([]string(nil), b.source.ReadOnlyRoots...)
		b.policy.DeniedRoots = append([]string(nil), b.source.DeniedRoots...)
		// RuntimeReadOnlyRoots are for sandbox executables, not model file tools.
	}
	return b
}

func (b *workspaceFilesystem) hiddenPath(path string) bool {
	for _, denied := range b.policy.DeniedRoots {
		if workspaceguard.Within(denied, path) {
			return true
		}
	}
	return false
}

func workspaceBoundaryError() error {
	return fmt.Errorf("workspace boundary: access denied; use the current workspace or result-artifact tools, never platform source/configuration")
}

// Check before Clean/Join, which would erase traversal components. Reject volume-
// relative Windows paths too; a bare drive or rooted path must not use the CWD.
func validateWorkspacePath(path string) error {
	for _, part := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if part == ".." {
			return workspaceBoundaryError()
		}
	}
	if strings.ContainsRune(path, '\x00') || (filepath.VolumeName(path) != "" && !filepath.IsAbs(path)) {
		return workspaceBoundaryError()
	}
	if filepath.Separator == '\\' && (strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\")) && !filepath.IsAbs(path) {
		return workspaceBoundaryError()
	}
	return nil
}

// openWorkspaceRoot pins each directory component before descending. Merely
// checking NoSymlink followed by os.OpenRoot(abs) has a TOCTOU gap at the root
// itself. OpenRoot relative to the parent, plus identity comparison, prevents a
// substituted symlink from selecting another directory during root acquisition.
// All subsequent operations stay relative to the final os.Root, not host paths.
func openWorkspaceRoot(abs string) (*os.Root, error) {
	if !filepath.IsAbs(abs) || filepath.Dir(filepath.Clean(abs)) == filepath.Clean(abs) {
		return nil, workspaceBoundaryError()
	}
	if err := validateWorkspacePath(abs); err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(abs)
	root, err := os.OpenRoot(volume + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimLeft(filepath.Clean(abs)[len(volume):], string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		before, statErr := root.Lstat(part)
		if statErr != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, workspaceBoundaryError()
		}
		next, openErr := root.OpenRoot(part)
		root.Close()
		if openErr != nil {
			return nil, openErr
		}
		after, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(before, after) {
			next.Close()
			return nil, workspaceBoundaryError()
		}
		root = next
	}
	return root, nil
}

// Caller owns root. Policy.Resolve supplies the policy/NoSymlink checks; os.Root
// supplies race-safe enforcement if a descendant changes after those checks.
func (b *workspaceFilesystem) resolve(ctx context.Context, path string, write bool) (root *os.Root, relative, absolute string, err error) {
	if b == nil || b.source == nil || workspaceguard.FromContext(ctx) != b.source {
		return nil, "", "", workspaceBoundaryError()
	}
	if err = ctx.Err(); err != nil {
		return nil, "", "", err
	}
	if err = validateWorkspacePath(path); err != nil {
		return nil, "", "", err
	}
	absolute, err = b.policy.Resolve(path, write)
	if err != nil {
		return nil, "", "", err
	}
	rootPath := b.policy.Workspace
	if !workspaceguard.Within(rootPath, absolute) {
		rootPath = ""
	}
	for _, ro := range b.policy.ReadOnlyRoots {
		if !filepath.IsAbs(ro) || !workspaceguard.Within(ro, absolute) {
			continue
		}
		if write {
			return nil, "", "", workspaceBoundaryError()
		}
		// A narrower read-only root remains its own os.Root, even if nested.
		if len(ro) > len(rootPath) {
			rootPath = ro
		}
	}
	if rootPath == "" {
		return nil, "", "", workspaceBoundaryError()
	}
	relative, err = filepath.Rel(rootPath, absolute)
	if err != nil {
		return nil, "", "", err
	}
	root, err = openWorkspaceRoot(rootPath)
	return root, relative, absolute, err
}

// Open each child directory separately, disallowing even in-bound symlinks.
// This also protects read-only subdirectories from symlink races during writes.
func workspaceDirectory(root *os.Root, path string, create bool) (*os.Root, error) {
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if part == "." {
			continue
		}
		before, err := current.Lstat(part)
		if create && os.IsNotExist(err) {
			if err = current.Mkdir(part, 0o700); err != nil && !os.IsExist(err) {
				current.Close()
				return nil, err
			}
			before, err = current.Lstat(part)
		}
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, workspaceBoundaryError()
		}
		next, err := current.OpenRoot(part)
		current.Close()
		if err != nil {
			return nil, err
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			next.Close()
			return nil, workspaceBoundaryError()
		}
		current = next
	}
	return current, nil
}

func workspaceRegularFile(root *os.Root, path string, flags int) (*os.File, error) {
	parent, err := workspaceDirectory(root, filepath.Dir(path), flags&os.O_CREATE != 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	path = filepath.Base(path)
	info, err := parent.Lstat(path)
	if err != nil && !(os.IsNotExist(err) && flags&os.O_CREATE != 0) {
		return nil, err
	}
	if err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("workspace boundary: only regular files are supported")
	}
	existed := err == nil
	if !existed {
		flags |= os.O_EXCL // A concurrently inserted symlink must not be followed.
	}
	file, err := parent.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || (existed && !os.SameFile(info, after)) {
		file.Close()
		return nil, workspaceBoundaryError()
	}
	return file, nil
}

func (b *workspaceFilesystem) Read(ctx context.Context, req *filesystem.ReadRequest) (*filesystem.FileContent, error) {
	if req == nil {
		return nil, fmt.Errorf("read request is required")
	}
	root, relative, _, err := b.resolve(ctx, req.FilePath, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := workspaceRegularFile(root, relative, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	offset, limit := req.Offset, req.Limit
	if offset <= 0 {
		offset = 1
	}
	if limit <= 0 {
		limit = 2000 // Same line-based defaults as Eino's read_file/local backend.
	}
	reader := bufio.NewReader(file)
	var out strings.Builder
	for line, taken := 1, 0; taken < limit; line++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		text, err := reader.ReadString('\n')
		if text != "" && line >= offset {
			out.WriteString(text)
			taken++
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
	}
	return &filesystem.FileContent{Content: strings.TrimSuffix(out.String(), "\n")}, nil
}

func (b *workspaceFilesystem) Write(ctx context.Context, req *filesystem.WriteRequest) error {
	if req == nil {
		return fmt.Errorf("write request is required")
	}
	root, relative, _, err := b.resolve(ctx, req.FilePath, true)
	if err != nil {
		return err
	}
	defer root.Close()
	// Truncate only after confirming the opened descriptor is a regular file.
	file, err := workspaceRegularFile(root, relative, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Truncate(0); err != nil {
		return err
	}
	_, err = io.WriteString(file, req.Content)
	return err
}

func (b *workspaceFilesystem) Edit(ctx context.Context, req *filesystem.EditRequest) error {
	if req == nil || req.OldString == "" || req.OldString == req.NewString {
		return fmt.Errorf("edit requires non-empty old_string and a different new_string")
	}
	root, relative, _, err := b.resolve(ctx, req.FilePath, true)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := workspaceRegularFile(root, relative, os.O_RDWR)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	text := string(data)
	count := strings.Count(text, req.OldString)
	if count == 0 {
		return fmt.Errorf("old_string not found in file")
	}
	if count > 1 && !req.ReplaceAll {
		return fmt.Errorf("old_string appears multiple times; use replace_all")
	}
	if !req.ReplaceAll {
		count = 1
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Use the same descriptor for read and write, never reopen an unchecked path.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	_, err = io.WriteString(file, strings.Replace(text, req.OldString, req.NewString, count))
	return err
}

func workspaceFileInfo(absolute string, info fs.FileInfo) filesystem.FileInfo {
	return filesystem.FileInfo{Path: absolute, IsDir: info.IsDir(), Size: info.Size(), ModifiedAt: info.ModTime().Format(time.RFC3339)}
}

func (b *workspaceFilesystem) LsInfo(ctx context.Context, req *filesystem.LsInfoRequest) ([]filesystem.FileInfo, error) {
	if req == nil {
		return nil, fmt.Errorf("ls request is required")
	}
	root, relative, absolute, err := b.resolve(ctx, req.Path, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), filepath.ToSlash(relative))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []filesystem.FileInfo
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if b.hiddenPath(filepath.Join(absolute, entry.Name())) {
			continue
		}
		info, err := root.Lstat(filepath.Join(relative, entry.Name()))
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			continue
		}
		out = append(out, workspaceFileInfo(filepath.Join(absolute, entry.Name()), info))
	}
	return out, nil
}

// Explicitly refuse the optional Shell interface. Streaming execution is wired
// separately via security.NewEinoStreamingShell; there is no Local fallback.
func (b *workspaceFilesystem) Execute(context.Context, *filesystem.ExecuteRequest) (*filesystem.ExecuteResponse, error) {
	return nil, fmt.Errorf("workspace filesystem execute is disabled; use the sandboxed streaming shell")
}
