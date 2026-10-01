package mcp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestExecutionServiceTerminalSaveFailureIsExplicitWithoutRetryOrStatusRewrite(t *testing.T) {
	for _, status := range []string{ToolExecutionStatusCompleted, ToolExecutionStatusFailed} {
		t.Run(status, func(t *testing.T) {
			dbErr := errors.New("database unavailable")
			storage := &terminalSaveFailureStorage{inMemoryMonitorStorage: newInMemoryMonitorStorage(), saveErr: dbErr}
			core, logs := observer.New(zap.DebugLevel)
			service := NewExecutionService(storage, zap.New(core))
			finished := make(chan *ToolExecution, 1)
			runErrText := "original tool error: \xfc\x00"
			handle, err := service.Submit(context.Background(), ExecutionRequest{
				ToolName: "exec",
				Run: func(context.Context) (*ToolResult, error) {
					if status == ToolExecutionStatusFailed {
						return nil, errors.New(runErrText)
					}
					return &ToolResult{Content: []Content{{Type: "text", Text: "合法中文"}}}, nil
				},
				OnDone: func(exec *ToolExecution) { finished <- exec },
			})
			if err != nil {
				t.Fatal(err)
			}
			var final *ToolExecution
			select {
			case final = <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not finish after failed save")
			}
			if final.ID != handle.ID || final.Status != status || final.EndTime == nil {
				t.Fatalf("tool's actual outcome was rewritten: %#v", final)
			}
			if status == ToolExecutionStatusFailed && final.Error != runErrText {
				t.Fatalf("original tool error was overwritten by storage error: %q", final.Error)
			}
			storage.mu.Lock()
			attempts := storage.terminalAttempts
			persisted := cloneToolExecution(storage.executions[handle.ID])
			storage.mu.Unlock()
			if attempts != 1 {
				t.Fatalf("terminal save attempts = %d, want exactly one", attempts)
			}
			if persisted == nil || persisted.Status != ToolExecutionStatusRunning || persisted.EndTime != nil {
				t.Fatalf("failed write was falsely represented as persisted: %#v", persisted)
			}
			errorLogs := logs.FilterLevelExact(zap.ErrorLevel).All()
			if len(errorLogs) != 1 {
				t.Fatalf("explicit terminal persistence errors = %d, want 1", len(errorLogs))
			}
			fields := errorLogs[0].ContextMap()
			if fields["executionId"] != handle.ID || fields["status"] != status || fields["error"] != dbErr.Error() {
				t.Fatalf("missing terminal save failure evidence: %#v", fields)
			}
		})
	}
}

type terminalSaveFailureStorage struct {
	*inMemoryMonitorStorage
	mu               sync.Mutex
	saveErr          error
	terminalAttempts int
}

func (s *terminalSaveFailureStorage) SaveToolExecution(exec *ToolExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isExecutionTerminal(exec.Status) {
		s.terminalAttempts++
		return s.saveErr
	}
	return s.inMemoryMonitorStorage.SaveToolExecution(exec)
}
