// Package workspaceguard defines the trusted, per-run filesystem boundary.
// Policies are service-generated and are never accepted from model arguments.
package workspaceguard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Policy struct {
	Workspace            string
	EvidenceRoot         string
	ReadOnlyRoots        []string
	RuntimeReadOnlyRoots []string
	RuntimeWritableRoots []string
	DeniedRoots          []string
}

type contextKey struct{}

func WithPolicy(ctx context.Context, p *Policy) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

func FromContext(ctx context.Context) *Policy {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(contextKey{}).(*Policy)
	return p
}

func Within(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Resolve rejects symlinks in every existing component, including a not-yet-created
// file's parents. Callers must additionally use os.Root for race-safe file I/O or
// the process mount namespace; string validation alone is not a sandbox.
func (p *Policy) Resolve(path string, write bool) (string, error) {
	if p == nil || !filepath.IsAbs(p.Workspace) {
		return "", fmt.Errorf("workspace boundary unavailable; refusing local file access")
	}
	if strings.TrimSpace(path) == "" {
		path = "."
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(p.Workspace, path)
	}
	path = filepath.Clean(path)
	for _, denied := range p.DeniedRoots {
		if Within(denied, path) {
			return "", fmt.Errorf("workspace boundary: private platform state is not accessible")
		}
	}
	allowed := Within(p.Workspace, path)
	if !write {
		for _, root := range p.ReadOnlyRoots {
			allowed = allowed || Within(root, path)
		}
	}
	if !allowed {
		return "", fmt.Errorf("workspace boundary: access denied; use the current workspace or the result-artifact tools, never platform source/configuration")
	}
	if err := NoSymlink(path); err != nil {
		return "", err
	}
	return path, nil
}

func NoSymlink(path string) error {
	path = filepath.Clean(path)
	for {
		st, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("workspace boundary: symbolic links are not allowed")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func EnsureDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err = NoSymlink(abs); err != nil {
		return "", err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return "", err
	}
	if err = NoSymlink(abs); err != nil {
		return "", err
	}
	return abs, nil
}
