package mcp

import (
	"context"
	"cyberstrike-ai/internal/authctx"
)

// Bind file layout to stored, trusted execution ownership rather than a path or
// project hint in tool arguments. Native workers reuse the start-time binding.
func storedExecutionProjectContext(ctx context.Context, storage MonitorStorage, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if storage == nil {
		return ctx
	}
	conv := MCPConversationIDFromContext(ctx)
	if id != "" {
		if bindings, ok := storage.(interface {
			ExecutionBoundProject(string, string, string) (string, error)
		}); ok {
			owner := ""
			if p, ok := authctx.PrincipalFromContext(ctx); ok {
				owner = p.UserID
			}
			if owner != "" && conv != "" {
				if pid, err := bindings.ExecutionBoundProject(id, conv, owner); err == nil {
					return WithMCPProjectID(ctx, pid)
				}
			}
		}
	}
	if projects, ok := storage.(interface{ GetConversationProjectID(string) (string, error) }); ok && conv != "" {
		if pid, err := projects.GetConversationProjectID(conv); err == nil {
			return WithMCPProjectID(ctx, pid)
		}
	}
	return ctx
}
