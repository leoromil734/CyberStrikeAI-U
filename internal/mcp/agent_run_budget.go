package mcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrFactWriteBudget      = errors.New("本次事实写入额度已用完：暂停新增或更新事实；实际工具验证、原件保存、漏洞记录和报告整理仍可继续。不要重复补写，也不得将未完成项标为已验证")
	ErrCoverageRepairBudget = errors.New("覆盖补写阶段已达到时间上限：停止自动续跑，保留已验证成果与未完成项")
)

type agentRunBudgetKey struct{}

// AgentRunBudget belongs to one explicit user request. All parallel roles and
// automatic continuation segments share it; new requests get a new instance.
// The fact quota limits validated mutations, not the lifetime of real tool work.
// Only explicit run/repair deadlines cancel the parent execution.
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

// Call after authorization, schema validation and no-op detection, immediately
// before mutation. Rejected fields and reads do not consume the mutation quota.
// The limit is snapshotted once and cannot be enlarged by continuation/config.
// Exhaustion rejects only fact writes, never cancels testing or report delivery.
func AdmitProjectFactWrite(ctx context.Context, limit int) error {
	b := AgentRunBudgetFromContext(ctx)
	if b == nil {
		return nil
	} // trusted non-agent API callers retain their contract
	if err := ctx.Err(); err != nil {
		return err
	}
	if limit <= 0 {
		limit = 1024
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
	err := fmt.Errorf("%w（本次请求有效写入上限 %d 次；失败的字段校验与无变化重试不占用额度）", ErrFactWriteBudget, b.limit)
	b.mu.Unlock()
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
