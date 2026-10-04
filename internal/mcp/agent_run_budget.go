package mcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrFactWriteBudget      = errors.New("事实写入预算已耗尽：停止批量补写，保留原始库存和未完成项，不得将其标记为已验证")
	ErrCoverageRepairBudget = errors.New("覆盖补写阶段已达到时间上限：停止自动续跑，保留已验证成果与未完成项")
)

type agentRunBudgetKey struct{}

// AgentRunBudget belongs to one explicit user request. All parallel roles and
// automatic continuation segments share it; new requests get a new instance.
// Admission occurs in the actual write handler, not asynchronously in SSE logs.
type AgentRunBudget struct {
	mu            sync.Mutex
	limit         int
	writes        int
	stopped       error
	cancel        context.CancelCauseFunc
	repairTimer   *time.Timer
	repairStarted bool
	closed        bool
}

func WithAgentRunBudget(ctx context.Context, cancel context.CancelCauseFunc) context.Context {
	b := AgentRunBudgetFromContext(ctx)
	if b == nil {
		b = &AgentRunBudget{}
	}
	b.mu.Lock()
	b.cancel = cancel
	stopped := b.stopped
	b.mu.Unlock()
	if stopped != nil && cancel != nil {
		cancel(stopped)
	}
	return context.WithValue(ctx, agentRunBudgetKey{}, b)
}

func AgentRunBudgetFromContext(ctx context.Context) *AgentRunBudget {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(agentRunBudgetKey{}).(*AgentRunBudget)
	return b
}

// Invalid and repeated model writes consume the budget as well. The first
// invocation snapshots the service limit; arguments cannot enlarge/reset it.
func AdmitProjectFactWrite(ctx context.Context, limit int) error {
	b := AgentRunBudgetFromContext(ctx)
	if b == nil {
		return nil
	} // trusted non-agent API callers retain their contract
	if err := ctx.Err(); err != nil {
		return err
	}
	if limit <= 0 {
		limit = 256
	}
	b.mu.Lock()
	if b.stopped != nil {
		err := b.stopped
		b.mu.Unlock()
		return err
	}
	if b.closed {
		b.mu.Unlock()
		return context.Canceled
	}
	if b.limit == 0 {
		b.limit = limit
	}
	if b.writes < b.limit {
		b.writes++
		b.mu.Unlock()
		return nil
	}
	b.stopped = fmt.Errorf("%w（本次请求上限 %d 次，包含创建、更新及失败重试）", ErrFactWriteBudget, b.limit)
	err, cancel := b.stopped, b.cancel
	b.mu.Unlock()
	if cancel != nil {
		cancel(err)
	}
	return err
}

// StartCoverageRepairBudget arms once, so subsequent segments cannot renew it.
// It cancels a stuck inner model/tool loop too, not just the next finalizer pass.
func StartCoverageRepairBudget(ctx context.Context, limit time.Duration) {
	b := AgentRunBudgetFromContext(ctx)
	if b == nil || limit <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.repairStarted || b.closed || b.stopped != nil {
		return
	}
	b.repairStarted = true
	b.repairTimer = time.AfterFunc(limit, func() { b.stop(ErrCoverageRepairBudget) })
}

func (b *AgentRunBudget) stop(cause error) {
	b.mu.Lock()
	if b.closed || b.stopped != nil {
		b.mu.Unlock()
		return
	}
	b.stopped = cause
	cancel := b.cancel
	b.mu.Unlock()
	if cancel != nil {
		cancel(cause)
	}
}

func CloseAgentRunBudget(ctx context.Context) {
	b := AgentRunBudgetFromContext(ctx)
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.repairTimer != nil {
		b.repairTimer.Stop()
	}
}

func IsAgentRunBudgetReason(code string) bool {
	return code == "fact_write_budget_exceeded" || code == "coverage_repair_budget_exceeded"
}

func AgentRunBudgetStopReason(cause error) string {
	switch {
	case errors.Is(cause, ErrFactWriteBudget):
		return "fact_write_budget_exceeded"
	case errors.Is(cause, ErrCoverageRepairBudget):
		return "coverage_repair_budget_exceeded"
	default:
		return ""
	}
}
