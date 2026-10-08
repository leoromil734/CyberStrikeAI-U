package pilab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// This exercises the actual PI SDK across the Go/Node protocol boundary. The
// model is a loopback-only SSE fixture; no model account or target is contacted.
func TestRealPISDKDelegationProtocol(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is unavailable")
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "runtimes", "pi-lab"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules", "@earendil-works", "pi-coding-agent", "package.json")); os.IsNotExist(err) {
		t.Skip("install the optional runtimes/pi-lab dependencies to run the real SDK fixture")
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer offline-fixture-key" {
			http.Error(w, "invalid fixture request", 400)
			return
		}
		n := calls.Add(1)
		var delta map[string]any
		finish := "stop"
		switch n {
		case 1:
			finish = "tool_calls"
			delta = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"index": 0, "id": "call_delegate", "type": "function", "function": map[string]any{"name": "delegate_agents", "arguments": `{"tasks":[{"name":"fixture-worker","task":"Use record_surface to record the provided fixture https://example.test; make no HTTP requests, then summarize."}]}`}}}}
		case 2:
			finish = "tool_calls"
			delta = map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"index": 0, "id": "call_surface", "type": "function", "function": map[string]any{"name": "record_surface", "arguments": `{"label":"Fixture surface","url":"https://example.test","detail":"Supplied offline fixture, not a network observation."}`}}}}
		case 3:
			delta = map[string]any{"role": "assistant", "content": "Worker recorded the supplied fixture surface. No HTTP checks were made."}
		case 4:
			delta = map[string]any{"role": "assistant", "content": "PI coordinator summary: one delegated worker and one supplied fixture surface. No confirmed vulnerabilities."}
		default:
			http.Error(w, "unexpected extra model call", 400)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, chunk := range []map[string]any{
			{"id": "fixture-response", "object": "chat.completion.chunk", "created": 1, "model": "fixture-model", "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}},
			{"id": "fixture-response", "object": "chat.completion.chunk", "created": 1, "model": "fixture-model", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": finish}}},
		} {
			raw, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", raw)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer server.Close()
	m := New(Options{Enabled: true, Root: t.TempDir(), Runtime: &ProcessRuntime{Node: node, Script: filepath.Join(dir, "runner.mjs")}})
	defer m.Close()
	model := fixtureModel()
	model.APIKey = "offline-fixture-key"
	model.BaseURL = server.URL + "/v1"
	req := fixtureRequest()
	req.MaxParallel = 1
	req.MaxAgents = 1
	req.Prompt = "Delegate the offline fixture analysis to one worker, then summarize. Do not contact any target."
	run, err := m.Create("alice", req, model)
	if err != nil {
		t.Fatal(err)
	}
	result := waitRun(t, m, run.ID)
	if result.Status != "completed" || len(result.Agents) != 2 || len(result.Nodes) == 0 || calls.Load() != 4 {
		page, _ := m.Events("alice", run.ID, 0)
		t.Fatalf("PI integration failed: status=%s error=%s agents=%d nodes=%d calls=%d events=%+v", result.Status, result.Error, len(result.Agents), len(result.Nodes), calls.Load(), page.Events)
	}
}
