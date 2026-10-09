package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestExternalHTTPRepeatGuardRunsAtDispatchNotSubmitOrWait(t *testing.T) {
	manager := NewExternalMCPManager(zap.NewNop())
	manager.toolWaitTimeout = 5 * time.Millisecond
	manager.ConfigureResilience(ExternalMCPResilienceConfig{MaxConcurrentPerServer: 1, MaxConcurrentTotal: 1, CircuitFailureThreshold: 1, CircuitCooldown: time.Hour})
	client := newBlockingExternalMCPClient("changing-response")
	manager.clients["lab"] = client
	var admitted, released atomic.Int32
	manager.SetExecutionGuard(func(ctx context.Context, name string, args map[string]interface{}) (func(), error) {
		if name != "http-framework-test" || MCPConversationIDFromContext(ctx) != "scoped-session" || args["url"] != "https://example.test/a" {
			return nil, fmt.Errorf("lost actual name, session or URL before dispatch")
		}
		if admitted.Add(1) > 5 {
			return nil, fmt.Errorf("fixture repeat allowance exhausted")
		}
		return func() { released.Add(1) }, nil
	})
	ctx := WithMCPConversationID(context.Background(), "scoped-session")
	args := map[string]interface{}{"url": "https://example.test/a", "conversation_id": "untrusted"}
	_, firstID, err := manager.CallTool(ctx, "lab::http-framework-test", args)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.started:
	case <-time.After(time.Second):
		t.Fatal("client did not start")
	}
	_, queuedID, err := manager.CallTool(ctx, "lab::http-framework-test", args)
	if err != nil {
		t.Fatal(err)
	}
	if admitted.Load() != 1 || client.count.Load() != 1 {
		t.Fatal("queued or soft-timeout invocation counted before client dispatch")
	}
	for i := 0; i < 2; i++ {
		_, _ = manager.executionService.Wait(ctx, firstID, time.Millisecond)
	}
	if admitted.Load() != 1 {
		t.Fatal("polling reserved the same invocation again")
	}
	close(client.release)
	for _, id := range []string{firstID, queuedID} {
		if _, err := manager.executionService.Wait(ctx, id, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	manager.toolWaitTimeout = time.Second
	for i := 2; i < 5; i++ {
		result, _, err := manager.CallTool(ctx, "lab::http-framework-test", args)
		if err != nil || result == nil || result.IsError {
			t.Fatalf("call %d: %+v %v", i+1, result, err)
		}
	}
	for i := 0; i < 2; i++ {
		result, _, err := manager.CallTool(ctx, "lab::http-framework-test", args)
		if err != nil || result == nil || !result.IsError || !strings.Contains(ToolResultPlainText(result), "repeat allowance") {
			t.Fatalf("guard denial lost or opened remote circuit: %+v %v", result, err)
		}
	}
	if client.count.Load() != 5 || released.Load() != 5 {
		t.Fatalf("actual client calls=%d releases=%d; want exactly five", client.count.Load(), released.Load())
	}
}
