package agent

import "context"

func (a *Agent) PrepareLocalExecutionContext(ctx context.Context, executionID string) context.Context {
	if a == nil || a.mcpServer == nil {
		return ctx
	}
	return a.mcpServer.PrepareLocalExecutionContext(ctx, executionID)
}
