package multiagent

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestToolInvokeCompletionBufferStoresDeterministically(t *testing.T) {
	buffer := newToolInvokeCompletionBuffer()
	buffer.Store(toolInvokeCompletion{ToolCallID: " call-b ", Content: "first"})
	buffer.Store(toolInvokeCompletion{ToolCallID: "call-a", Content: "a"})
	buffer.Store(toolInvokeCompletion{ToolCallID: "call-b", Content: "latest"})
	buffer.Store(toolInvokeCompletion{ToolCallID: "   ", Content: "ignored"})

	got := buffer.Snapshot()
	if len(got) != 2 {
		t.Fatalf("snapshot length = %d, want 2", len(got))
	}
	if got[0].ToolCallID != "call-a" || got[1].ToolCallID != "call-b" {
		t.Fatalf("snapshot order = [%q, %q]", got[0].ToolCallID, got[1].ToolCallID)
	}
	if got[1].Content != "latest" {
		t.Fatalf("duplicate completion did not replace prior value: %+v", got[1])
	}

	buffer.Delete(" call-a ")
	got = buffer.Snapshot()
	if len(got) != 1 || got[0].ToolCallID != "call-b" {
		t.Fatalf("snapshot after delete = %+v", got)
	}
}

func TestToolInvokeCompletionBufferWaitForChange(t *testing.T) {
	buffer := newToolInvokeCompletionBuffer()
	_, version := buffer.SnapshotWithVersion()
	stored := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		buffer.Store(toolInvokeCompletion{ToolCallID: "call-late", Content: "done"})
		close(stored)
	}()

	if !buffer.WaitForChange(context.Background(), version, time.Second) {
		t.Fatal("expected late completion to wake waiter")
	}
	<-stored
	got := buffer.Snapshot()
	if len(got) != 1 || got[0].ToolCallID != "call-late" {
		t.Fatalf("late completion missing: %+v", got)
	}
}

func TestToolInvokeCompletionBufferWaitObservesStoreAfterSnapshot(t *testing.T) {
	buffer := newToolInvokeCompletionBuffer()
	_, version := buffer.SnapshotWithVersion()
	buffer.Store(toolInvokeCompletion{ToolCallID: "call-between", Content: "done"})

	start := time.Now()
	if !buffer.WaitForChange(context.Background(), version, time.Second) {
		t.Fatal("store after snapshot must be observed without another notification")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("version mismatch should return immediately, took %v", elapsed)
	}
}

func TestToolInvokeCompletionBufferWaitStopsOnTimeoutAndCancel(t *testing.T) {
	buffer := newToolInvokeCompletionBuffer()
	_, version := buffer.SnapshotWithVersion()
	if buffer.WaitForChange(context.Background(), version, 10*time.Millisecond) {
		t.Fatal("timeout without completion must return false")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if buffer.WaitForChange(ctx, version, time.Second) {
		t.Fatal("cancelled wait must return false")
	}
}

func TestToolInvokeCompletionBufferConcurrentStores(t *testing.T) {
	buffer := newToolInvokeCompletionBuffer()
	const count = 64
	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("call-%02d", i)
			buffer.Store(toolInvokeCompletion{ToolCallID: id, Content: id})
		}()
	}
	wg.Wait()

	got := buffer.Snapshot()
	if len(got) != count {
		t.Fatalf("snapshot length = %d, want %d", len(got), count)
	}
	for i, completion := range got {
		want := fmt.Sprintf("call-%02d", i)
		if completion.ToolCallID != want || completion.Content != want {
			t.Fatalf("completion %d = %+v, want %q", i, completion, want)
		}
	}
}
