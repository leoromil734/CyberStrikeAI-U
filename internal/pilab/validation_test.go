package pilab

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScopeAndBudgetValidation(t *testing.T) {
	for _, scope := range []string{"https://example.test/path", "https://*.example.test", "file:///etc/passwd", "http://localhost", "http://127.0.0.1", "http://127.1", "http://2130706433", "http://0x7f000001", "http://[::1]", "http://169.254.169.254", "http://metadata.google.internal", "https://user:pass@example.test", "https://example.test?", "https://example.test#fragment", "https://example.test:65536", "http://0.0.0.0", "http://[fe80::1]", "http://192.168.1.2", "http://10.1.2.3", "http://172.16.1.2", "http://[fd00::1]"} {
		req := fixtureRequest()
		req.Scope = []string{scope}
		if _, _, err := ValidateRequest(req); err == nil {
			t.Errorf("unsafe scope accepted: %s", scope)
		}
	}
	req := fixtureRequest()
	req.Scope = []string{"https://EXAMPLE.test:443/", "https://example.test"}
	normalized, _, err := ValidateRequest(req)
	if err != nil || len(normalized.Scope) != 1 || normalized.Scope[0] != "https://example.test" {
		t.Fatal(normalized, err)
	}
	req = fixtureRequest()
	req.Authorized = false
	if _, _, err := ValidateRequest(req); err == nil {
		t.Fatal("missing authorization accepted")
	}
	for _, limits := range []Limits{{MaxParallel: 5}, {MaxParallel: -1}, {MaxAgents: 13}, {TimeoutSeconds: 59}, {TimeoutSeconds: 1801}} {
		req = fixtureRequest()
		req.MaxParallel = limits.MaxParallel
		req.MaxAgents = limits.MaxAgents
		req.TimeoutSeconds = limits.TimeoutSeconds
		if _, _, err := ValidateRequest(req); err == nil {
			t.Fatal("bad budget accepted", limits)
		}
	}
}

func TestProcessRuntimeProtocolAndEnvironment(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is unavailable")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fixture.mjs")
	// A hermetic protocol peer. It never calls a model or target.
	body := `
if (process.argv.includes('--check')) { console.log(JSON.stringify({ready:true,runtime:'pi-coding-agent'})); }
else {
 let s=''; for await (const chunk of process.stdin) s+=chunk;
 const input=JSON.parse(s);
 if(process.env.PI_TEST_PRIVATE || process.env.NODE_OPTIONS) process.exit(2);
 console.error('stderr secret: '+input.model.api_key);
 console.log(JSON.stringify({type:'report',agent_id:'coordinator',data:{text:input.prompt}}));
 console.log(JSON.stringify({type:'complete',data:{status:'completed'}}));
}
`
	if err := os.WriteFile(script, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_TEST_PRIVATE", "must-not-inherit")
	t.Setenv("NODE_OPTIONS", "--trace-warnings")
	runtime := &ProcessRuntime{Node: node, Script: script}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.Check(ctx); err != nil {
		t.Fatal(err)
	}
	var events []Event
	if err := runtime.Run(ctx, dir, Input{Prompt: "local fixture", Model: fixtureModel()}, func(ev Event) error { events = append(events, ev); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "report" {
		t.Fatal(events)
	}
	for _, event := range events {
		if strings.Contains(string(event.Data), "secret-key") {
			t.Fatal("stderr exposed")
		}
	}
}

func TestProcessRuntimeCancellation(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is unavailable")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "waiting.mjs")
	if err := os.WriteFile(script, []byte("setInterval(()=>{},1000);"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = (&ProcessRuntime{Node: node, Script: script}).Run(ctx, dir, Input{}, func(Event) error { return nil })
	if err == nil || time.Since(start) > 4*time.Second {
		t.Fatal("process was not cancelled", err)
	}
}
