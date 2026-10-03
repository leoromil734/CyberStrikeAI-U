package security

import (
	"context"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Inject only service-generated identifiers. A tool-reported path or an argument
// named work_dir never controls this managed evidence directory.
func (e *Executor) applyExecutionArtifactEnv(ctx context.Context, cmd *exec.Cmd) error {
	id := mcp.MCPExecutionIDFromContext(ctx)
	if id == "" {
		return nil
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("invalid service execution id")
	}
	opts := e.spillOptsFromContext(ctx)
	binding := evidence.Execution{ID: id, Access: evidence.Access{ProjectID: opts.ProjectID, ConversationID: opts.ConversationID}}
	root, err := evidence.ReductionRoot(opts.RootDir, binding)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(root.Path), "executions", id)
	if err = ensureArtifactDirectory(dir); err != nil {
		return err
	}
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	env := make([]string, 0, len(cmd.Env)+2)
	for _, v := range cmd.Env {
		if !strings.HasPrefix(v, "CSAI_EXECUTION_ID=") && !strings.HasPrefix(v, "CSAI_ARTIFACT_DIR=") {
			env = append(env, v)
		}
	}
	cmd.Env = append(env, "CSAI_EXECUTION_ID="+id, "CSAI_ARTIFACT_DIR="+dir)
	return nil
}
func ensureArtifactDirectory(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return evidence.ErrUnsafePath
	}
	parent := filepath.Dir(path)
	if parent != path {
		if err := ensureArtifactDirectory(parent); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return evidence.ErrUnsafePath
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(path, filepath.Clean(resolved)) {
		return evidence.ErrUnsafePath
	}
	return nil
}
