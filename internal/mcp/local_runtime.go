package mcp

import "context"

// LocalExecutionRuntime is trusted service configuration for native ADK shell
// executions. It shares the configured process budget with named MCP tools.
type LocalExecutionRuntime struct {
	SpillRoot      string
	MaxOutputBytes int
	Acquire        func(context.Context, string, map[string]interface{}) (func(), error)
	Activity       chan struct{}
}
type localRuntimeKey struct{}

func WithLocalExecutionRuntime(ctx context.Context, r LocalExecutionRuntime) context.Context {
	return context.WithValue(ctx, localRuntimeKey{}, r)
}
func LocalExecutionRuntimeFromContext(ctx context.Context) (LocalExecutionRuntime, bool) {
	r, ok := ctx.Value(localRuntimeKey{}).(LocalExecutionRuntime)
	return r, ok
}
func NotifyLocalExecutionActivity(ctx context.Context) {
	if r, ok := LocalExecutionRuntimeFromContext(ctx); ok && r.Activity != nil {
		select {
		case r.Activity <- struct{}{}:
		default:
		}
	}
}
func (s *Server) SetLocalExecutionGuard(guard func(context.Context, string, map[string]interface{}) (func(), error)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.localExecutionGuard = guard
	s.mu.Unlock()
}
func (s *Server) PrepareLocalExecutionContext(ctx context.Context, id string) context.Context {
	ctx = WithMCPExecutionID(ctx, id)
	if s == nil {
		return ctx
	}
	ctx = storedExecutionProjectContext(ctx, s.storage, id)
	s.mu.RLock()
	r := LocalExecutionRuntime{SpillRoot: s.spillRootDir, MaxOutputBytes: s.toolResultMaxBytes, Acquire: s.localExecutionGuard, Activity: make(chan struct{}, 1)}
	s.mu.RUnlock()
	return WithLocalExecutionRuntime(ctx, r)
}
