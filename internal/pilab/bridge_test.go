package pilab

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func bridgeInput(execute ToolExecutor) Input {
	return Input{Mode: ModePlatform, Limits: DefaultPlatformLimits, Platform: &PlatformInput{Tools: []ToolDefinition{{Name: "fixture", InputSchema: map[string]interface{}{"type": "object"}}}}, Execute: execute}
}
func callBridge(t *testing.T, b *toolBridge, token string, call any, mutate func(*http.Request)) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(call)
	req, _ := http.NewRequest(http.MethodPost, b.config.URL, bytes.NewReader(raw))
	req.Header.Set("Authorization", token)
	if mutate != nil {
		mutate(req)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, body
}
func TestToolBridgeAuthenticationAllowlistAndContext(t *testing.T) {
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "bound-principal")
	var calls atomic.Int32
	b, err := startToolBridge(ctx, bridgeInput(func(ctx context.Context, call ToolCall) (*ToolReply, error) {
		calls.Add(1)
		if ctx.Value(key{}) != "bound-principal" {
			t.Error("lost run context")
		}
		return &ToolReply{ExecutionID: "e1", Content: []ToolContent{{Type: "text", Text: "observed"}}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	call := ToolCall{Name: "fixture", Arguments: map[string]interface{}{}, AgentID: "coordinator"}
	for _, sample := range []struct {
		token  string
		call   any
		mutate func(*http.Request)
		status int
	}{
		{"", call, nil, 401},
		{"Bearer wrong", call, nil, 401},
		{"Bearer " + b.config.Token, ToolCall{Name: "unknown", AgentID: "coordinator"}, nil, 403},
		{"Bearer " + b.config.Token, ToolCall{Name: "fixture", AgentID: "../foreign"}, nil, 403},
		{"Bearer " + b.config.Token, call, func(r *http.Request) { r.Header.Set("Origin", "https://untrusted.invalid") }, 403},
		{"Bearer " + b.config.Token, call, func(r *http.Request) { r.Host = "different.invalid" }, 403},
		{"Bearer " + b.config.Token, map[string]interface{}{"name": "fixture", "agent_id": "coordinator", "principal": "injected"}, nil, 400},
	} {
		code, _ := callBridge(t, b, sample.token, sample.call, sample.mutate)
		if code != sample.status {
			t.Fatalf("got %d want %d", code, sample.status)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected call executed")
	}
	code, body := callBridge(t, b, "Bearer "+b.config.Token, call, nil)
	if code != 200 || !strings.Contains(string(body), "e1") || calls.Load() != 1 {
		t.Fatal(code, string(body), calls.Load())
	}
}

func TestToolBridgeBudgetIsSharedAcrossWorkers(t *testing.T) {
	var calls, active, maxActive atomic.Int32
	input := bridgeInput(func(_ context.Context, _ ToolCall) (*ToolReply, error) {
		calls.Add(1)
		n := active.Add(1)
		for old := maxActive.Load(); n > old; old = maxActive.Load() {
			if maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		return &ToolReply{Content: []ToolContent{{Type: "text", Text: "done"}}}, nil
	})
	input.Limits.MaxToolCalls = 3
	input.Limits.MaxParallel = 2
	b, err := startToolBridge(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	codes := make(chan int, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := callBridge(t, b, "Bearer "+b.config.Token, ToolCall{Name: "fixture", AgentID: "worker-1"}, nil)
			codes <- code
		}()
	}
	wg.Wait()
	close(codes)
	ok, limited := 0, 0
	for code := range codes {
		if code == 200 {
			ok++
		} else if code == 429 {
			limited++
		} else {
			t.Fatal(code)
		}
	}
	if ok != 3 || limited != 3 || calls.Load() != 3 || maxActive.Load() > 2 {
		t.Fatal(ok, limited, calls.Load(), maxActive.Load())
	}
}

func TestToolBridgeCancellationStopsActiveAndQueuedCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	done := make(chan struct{})
	input := bridgeInput(func(ctx context.Context, _ ToolCall) (*ToolReply, error) {
		close(started)
		<-ctx.Done()
		close(done)
		return nil, ctx.Err()
	})
	input.Limits.MaxParallel = 1
	b, err := startToolBridge(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		callBridge(t, b, "Bearer "+b.config.Token, ToolCall{Name: "fixture", AgentID: "coordinator"}, nil)
	}()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("active call did not cancel")
	}
	<-finished
	code, _ := callBridge(t, b, "Bearer "+b.config.Token, ToolCall{Name: "fixture", AgentID: "coordinator"}, nil)
	if code != 410 {
		t.Fatal(code)
	}
}

func TestToolBridgeTruncatesHugeResultsToExecutionReference(t *testing.T) {
	b, err := startToolBridge(context.Background(), bridgeInput(func(context.Context, ToolCall) (*ToolReply, error) {
		return &ToolReply{ExecutionID: "saved-execution", Content: []ToolContent{{Type: "text", Text: strings.Repeat("X", bridgeReplyLimit+1)}}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	code, body := callBridge(t, b, "Bearer "+b.config.Token, ToolCall{Name: "fixture", AgentID: "coordinator"}, nil)
	if code != 200 || len(body) > 4096 || !strings.Contains(string(body), "saved-execution") {
		t.Fatal(code, len(body), string(body[:min(len(body), 200)]))
	}
}
