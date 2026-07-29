package multiagent

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type toolInvokeCompletion struct {
	ToolCallID string
	ToolName   string
	EinoAgent  string
	Success    bool
	Content    string
	InvokeErr  error
}

// toolInvokeCompletionBuffer 暂存工具桥已经完成、但 ADK Tool 事件尚未到达的结果。
// 正常路径由 ADK reduction 后的结果消费；仅在运行结束事件丢失时用于补齐。
type toolInvokeCompletionBuffer struct {
	mu      sync.Mutex
	byID    map[string]toolInvokeCompletion
	changed chan struct{}
	version uint64
}

func newToolInvokeCompletionBuffer() *toolInvokeCompletionBuffer {
	return &toolInvokeCompletionBuffer{
		byID:    make(map[string]toolInvokeCompletion),
		changed: make(chan struct{}),
	}
}

func (b *toolInvokeCompletionBuffer) Store(completion toolInvokeCompletion) {
	if b == nil {
		return
	}
	toolCallID := strings.TrimSpace(completion.ToolCallID)
	if toolCallID == "" {
		return
	}
	completion.ToolCallID = toolCallID
	b.mu.Lock()
	b.ensureInitializedLocked()
	b.byID[toolCallID] = completion
	b.version++
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
}

func (b *toolInvokeCompletionBuffer) Delete(toolCallID string) {
	if b == nil {
		return
	}
	toolCallID = strings.TrimSpace(toolCallID)
	if toolCallID == "" {
		return
	}
	b.mu.Lock()
	delete(b.byID, toolCallID)
	b.mu.Unlock()
}

func (b *toolInvokeCompletionBuffer) Snapshot() []toolInvokeCompletion {
	snapshot, _ := b.SnapshotWithVersion()
	return snapshot
}

func (b *toolInvokeCompletionBuffer) SnapshotWithVersion() ([]toolInvokeCompletion, uint64) {
	if b == nil {
		return nil, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]toolInvokeCompletion, 0, len(b.byID))
	for _, completion := range b.byID {
		out = append(out, completion)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ToolCallID < out[j].ToolCallID
	})
	return out, b.version
}

// WaitForChange 等待 afterVersion 之后的新通知。如果 Store 已发生在快照和等待之间，
// 版本差异会立即返回，不依赖通道订阅时机。
func (b *toolInvokeCompletionBuffer) WaitForChange(ctx context.Context, afterVersion uint64, timeout time.Duration) bool {
	if b == nil || timeout <= 0 {
		return false
	}
	b.mu.Lock()
	b.ensureInitializedLocked()
	if b.version != afterVersion {
		b.mu.Unlock()
		return true
	}
	changed := b.changed
	b.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-changed:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

func (b *toolInvokeCompletionBuffer) ensureInitializedLocked() {
	if b.byID == nil {
		b.byID = make(map[string]toolInvokeCompletion)
	}
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
}
