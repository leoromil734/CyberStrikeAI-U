package mcp

import (
	"context"
	"go.uber.org/zap"
)

// SetExecutionObserver receives trusted execution metadata before the terminal
// persistence attempt. It must persist a pending ingestion marker synchronously
// and queue bounded offline work; it cannot change or execute the tool result.
func (s *Server) SetExecutionObserver(observer func(context.Context, *ToolExecution)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.executionObserver = observer
	s.mu.Unlock()
	if s.executionService != nil {
		s.executionService.SetExecutionObserver(s.notifyExecutionObserver)
	}
}
func (s *Server) notifyExecutionObserver(ctx context.Context, e *ToolExecution) {
	if s == nil || e == nil {
		return
	}
	s.mu.RLock()
	observer := s.executionObserver
	s.mu.RUnlock()
	safeExecutionObserver(ctx, e, observer, s.logger)
}
func (m *ExternalMCPManager) SetExecutionObserver(observer func(context.Context, *ToolExecution)) {
	if m != nil && m.executionService != nil {
		m.executionService.SetExecutionObserver(func(ctx context.Context, e *ToolExecution) { safeExecutionObserver(ctx, e, observer, m.logger) })
	}
}
func (s *ExecutionService) SetExecutionObserver(observer func(context.Context, *ToolExecution)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.observer = observer
	s.mu.Unlock()
}
func safeExecutionObserver(ctx context.Context, e *ToolExecution, observer func(context.Context, *ToolExecution), logger *zap.Logger) {
	if observer == nil || e == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() {
		if r := recover(); r != nil && logger != nil {
			logger.Error("execution result observer panic; original execution is retained", zap.String("executionId", e.ID))
		}
	}()
	observer(context.WithoutCancel(ctx), cloneToolExecution(e))
}
