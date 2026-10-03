package multiagent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/workspaceguard"

	"github.com/cloudwego/eino/adk/middlewares/plantask"
)

// Plan persistence is writable only in this run's workspace, never in skills.
// Embed the guarded backend (not Local), including for model-supplied task IDs.
type workspacePlantaskBackend struct{ *workspaceFilesystem }

var _ plantask.Backend = (*workspacePlantaskBackend)(nil)

func (b *workspacePlantaskBackend) Delete(ctx context.Context, req *plantask.DeleteRequest) error {
	if req == nil || strings.TrimSpace(req.FilePath) == "" {
		return fmt.Errorf("plantask delete path is required")
	}
	root, relative, _, err := b.resolve(ctx, req.FilePath, true)
	if err != nil {
		return err
	}
	defer root.Close()
	parent, err := workspaceDirectory(root, filepath.Dir(relative), false)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Remove(filepath.Base(relative))
}

func prepareWorkspacePlantask(ctx context.Context, configuredRel, conversationID string) (*workspacePlantaskBackend, string, error) {
	policy := workspaceguard.FromContext(ctx)
	if policy == nil {
		return nil, "", workspaceBoundaryError()
	}
	rel := strings.TrimSpace(configuredRel)
	if rel == "" {
		rel = ".eino/plantask"
	}
	if err := validateWorkspacePath(rel); err != nil {
		return nil, "", err
	}
	if !filepath.IsLocal(rel) {
		return nil, "", workspaceBoundaryError()
	}
	rel = filepath.Clean(rel)
	// Preserve custom relative directories while always containing plan state in
	// workspace/.eino. Existing values such as .eino/plantask retain their path.
	if first := strings.Split(filepath.ToSlash(rel), "/")[0]; first != ".eino" {
		rel = filepath.Join(".eino", rel)
	}
	baseDir := filepath.Join(policy.Workspace, rel, sanitizeEinoPathSegment(conversationID))
	backend := &workspacePlantaskBackend{newWorkspaceFilesystem(ctx)}
	root, relative, _, err := backend.resolve(ctx, baseDir, true)
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	dir, err := workspaceDirectory(root, relative, true)
	if err != nil {
		return nil, "", err
	}
	dir.Close()
	return backend, baseDir, nil
}
