package mcp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExecutionSnapshotsSynchronizeConcurrentOutputAndWait(t *testing.T) {
	service := NewExecutionService(nil, nil)
	started, finish := make(chan struct{}), make(chan struct{})
	handle, err := service.Submit(context.Background(), ExecutionRequest{
		ToolName: "snapshot-fixture",
		Run: func(context.Context) (*ToolResult, error) {
			close(started)
			<-finish
			return &ToolResult{Content: []Content{{Type: "text", Text: "complete"}}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(finish)
		if _, err := service.Wait(context.Background(), handle.ID, time.Second); err != nil {
			t.Errorf("worker did not finish: %v", err)
		}
	})
	<-started
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	updated := make(chan struct{})
	go func() {
		defer close(updated)
		for i := 0; i < 2000; i++ {
			service.AppendPartialOutput(handle.ID, "x")
		}
	}()
	var first *ExecutionSnapshot
	for i := 0; i < 2000; i++ {
		snapshot, err := service.Get(handle.ID)
		if err != nil || snapshot == nil || snapshot.Execution.Status != ToolExecutionStatusRunning {
			t.Fatalf("invalid live snapshot: %+v %v", snapshot, err)
		}
		if first == nil {
			first = snapshot
		}
		waiting, err := service.Wait(cancelled, handle.ID, 0)
		if !errors.Is(err, context.Canceled) || waiting == nil || waiting.Execution.Status != ToolExecutionStatusRunning {
			t.Fatalf("cancelled wait lost live snapshot: %+v %v", waiting, err)
		}
	}
	<-updated
	last, err := service.Get(handle.ID)
	if err != nil || last.Execution.PartialOutputBytes != 2000 {
		t.Fatalf("lost concurrent output: %+v %v", last, err)
	}
	first.Execution.Status = "caller-mutation"
	if last.Execution.Status != ToolExecutionStatusRunning {
		t.Fatal("snapshots share mutable execution state")
	}
}
