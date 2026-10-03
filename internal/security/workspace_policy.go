package security

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/project"
	"cyberstrike-ai/internal/tooloutput"
	"cyberstrike-ai/internal/workspaceguard"
)

// NewWorkspacePolicy binds a run to service-selected project/conversation paths.
// It deliberately does not grant access to the application directory or config.
func NewWorkspacePolicy(cfg *config.Config, projectID, conversationID string) (*workspaceguard.Policy, error) {
	if cfg == nil || (strings.TrimSpace(projectID) == "" && strings.TrimSpace(conversationID) == "") {
		return nil, fmt.Errorf("local execution requires a project or conversation workspace")
	}
	workspace, err := workspaceguard.EnsureDir(project.WorkspaceRootDir(cfg.Agent.WorkspaceRootDir, projectID, conversationID))
	if err != nil {
		return nil, err
	}
	p := &workspaceguard.Policy{Workspace: workspace}
	// Reduction is read-only to model tools. Its writer is trusted middleware.
	base := cfg.MultiAgent.EinoMiddleware.ReductionRootDir
	if strings.TrimSpace(base) == "" {
		base = filepath.Join("tmp", "reduction")
	}
	reduction, err := workspaceguard.EnsureDir(project.WorkspaceRootDir(base, projectID, conversationID))
	if err != nil {
		return nil, err
	}
	p.ReadOnlyRoots = append(p.ReadOnlyRoots, reduction)
	p.EvidenceRoot = reduction
	if skills := strings.TrimSpace(cfg.SkillsDir); skills != "" {
		abs, err := filepath.Abs(skills)
		if err != nil {
			return nil, err
		}
		if workspaceguard.Within(abs, workspace) || abs == filepath.VolumeName(abs)+string(filepath.Separator) {
			return nil, fmt.Errorf("skills directory must not expose a workspace ancestor or filesystem root")
		}
		if err = workspaceguard.NoSymlink(abs); err != nil {
			return nil, err
		}
		p.ReadOnlyRoots = append(p.ReadOnlyRoots, abs)
		p.DeniedRoots = append(p.DeniedRoots, filepath.Join(abs, ".eino"))
	}
	p.RuntimeReadOnlyRoots = append([]string(nil), cfg.Security.LocalSandboxRuntimePaths...)
	p.RuntimeWritableRoots = append([]string(nil), cfg.Security.LocalSandboxWritableRuntimePaths...)
	return p, nil
}

func (e *Executor) workspaceContext(ctx context.Context) (context.Context, error) {
	if workspaceguard.FromContext(ctx) != nil {
		return ctx, nil
	}
	// Standalone unit fixtures without server configuration keep their existing
	// execution contract. Production always installs credentialConfig at startup.
	if e == nil || e.credentialConfig == nil {
		return ctx, nil
	}
	conv := mcp.MCPConversationIDFromContext(ctx)
	unscoped := strings.TrimSpace(conv) == "" && mcp.MCPProjectIDFromContext(ctx) == ""
	if conv == "" {
		conv = mcp.MCPExecutionIDFromContext(ctx)
	}
	p, err := NewWorkspacePolicy(e.credentialConfig, mcp.MCPProjectIDFromContext(ctx), conv)
	if err != nil {
		return ctx, err
	}
	if unscoped {
		// Standalone MCP calls have no conversation row. Give each execution its
		// own workspace, and expose only its own evidence (never all "default").
		artifact, err := filepath.Abs(filepath.Join(tooloutput.SessionRoot(e.spillRootDir, "", ""), "executions", mcp.MCPExecutionIDFromContext(ctx)))
		if err != nil {
			return ctx, err
		}
		p.ReadOnlyRoots[0] = artifact
		p.EvidenceRoot = artifact
	}
	return workspaceguard.WithPolicy(ctx, p), nil
}
