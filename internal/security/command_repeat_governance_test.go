package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCommandResultFingerprintDynamicHTTP(t *testing.T) {
	response := func(date, nonce, timestamp string) string {
		return "HTTP/2 404 Not Found\r\nDate: " + date + "\r\nContent-Type: application/json\r\nX-Request-ID: " + nonce + "\r\nContent-Length: " + fmt.Sprint(len(nonce)) + "\r\n\r\n" +
			`{"timestamp":"` + timestamp + `","nonce":"` + nonce + `","code":404,"data":{"id":123,"message":"not found"}}`
	}
	a := response("Fri, 09 Oct 2026 00:00:00 GMT", "abc", "2026-10-09T00:00:00Z")
	b := response("Fri, 09 Oct 2026 00:00:01 GMT", "changed-long-nonce", "2026-10-09T00:00:01Z")
	if commandResultFingerprintOf(a) != commandResultFingerprintOf(b) {
		t.Fatal("HTTP metadata variation should not hide a stable response")
	}
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	for _, response := range []string{a, b, a} {
		recordCommandRun(ctx, "curl -i https://example.test/a", response)
	}
	if _, blocked := enforceCommandRepeatGuard(ctx, "curl -i https://example.test/a"); !blocked {
		t.Fatal("dynamic HTTP responses did not trigger stable-command stop")
	}
}

func TestCommandResultFingerprintPreservesMeaningfulDifferences(t *testing.T) {
	prefix := "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n" + strings.Repeat("same-prefix", 100)
	for _, pair := range [][2]string{
		{prefix + "allowed", prefix + "denied"},
		{"HTTP/2 200\nContent-Type: application/json\n\n{}", "HTTP/2 403\nContent-Type: application/json\n\n{}"},
		{`{"id":9007199254740992}`, `{"id":9007199254740993}`},
		{`{"code":401,"price":100}`, `{"code":403,"price":100}`},
		{`{"data":{"timestamp":123}}`, `{"data":{"timestamp":124}}`},
		{`{"url":"https://a.test/?nonce=1"}`, `{"url":"https://a.test/?nonce=2"}`},
		{`{"message":"a  b"}`, `{"message":"a b"}`},
		{`{"id":1,"id":2}`, `{"id":9,"id":2}`},
		{`{"id":1}`, `json:{"id":1}`},
		{"HTTP/2 302\nLocation: /a?id=1\n\n", "HTTP/2 302\nLocation: /a?id=2\n\n"},
		{`<script>const x = ' nonce="one"';</script>`, `<script>const x = ' nonce="two"';</script>`},
		{`<script data-test=' nonce="one"'></script>`, `<script data-test=' nonce="two"'></script>`},
		{`<!-- <script nonce="one"> -->`, `<!-- <script nonce="two"> -->`},
	} {
		if commandResultFingerprintOf(pair[0]) == commandResultFingerprintOf(pair[1]) {
			t.Fatalf("meaningful difference disappeared: %q / %q", pair[0], pair[1])
		}
	}
	if a, b := commandResultFingerprintOf(`<script nonce="one">go(123)</script>`), commandResultFingerprintOf(`<script nonce="two">go(123)</script>`); a != b {
		t.Fatal("CSP nonce variation should normalize")
	}
	if commandResultFingerprintOf("<persisted-output>preview</persisted-output>") != "" {
		t.Fatal("a partial preview cannot prove stability")
	}
}

func TestCommandFingerprintPreservesShellSemantics(t *testing.T) {
	for _, pair := range [][2]string{
		{`printf '%s' 'a  b'`, `printf '%s' 'a b'`},
		{`printf '%s' "a  b"`, `printf '%s' "a b"`},
		{"python3 -c 'if True:\n  print(1)\n  print(2)'", "python3 -c 'if True:\n  print(1)\nprint(2)'"},
		{"python3 <<'PY'\nif True:\n  print(1)\nPY", "python3 <<'PY'\nif True:\nprint(1)\nPY"},
		{"echo a\necho b", "echo a echo b"},
		{`echo a\ `, `echo a\`},
		{`echo "$HOME"`, `echo '$HOME'`},
		{"echo a # note\necho b", "echo a # note echo b"},
	} {
		if commandFingerprintOf(pair[0]) == commandFingerprintOf(pair[1]) {
			t.Fatalf("shell semantics merged: %q / %q", pair[0], pair[1])
		}
	}
}

func TestCommandResultFingerprintNativeFullStream(t *testing.T) {
	var first, second commandRepeatOutput
	for _, output := range []*commandRepeatOutput{&first, &second} {
		_, _ = output.Write([]byte(strings.Repeat("a", repeatResultBufferBytes+100)))
	}
	_, _ = first.Write([]byte("one"))
	_, _ = second.Write([]byte("two"))
	var a, b string
	first.record(func(fingerprint, _ string) { a = fingerprint })
	second.record(func(fingerprint, _ string) { b = fingerprint })
	if a == "" || a == b {
		t.Fatal("full stream tail was not included")
	}
}

func takeRepeatSlot(t *testing.T, ctx context.Context, tool string, args map[string]interface{}) {
	t.Helper()
	release, err := AcquireHTTPRepeatGuard(ctx, tool, args)
	if err != nil {
		t.Fatalf("unexpected admission failure: %v", err)
	}
	release()
	release() // Completion must be idempotent.
}

func TestHTTPRepeatLimitIgnoresResponseAndCommandOptions(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	for i := 0; i < httpRepeatLimit; i++ {
		tool := "exec"
		if i%2 == 1 {
			tool = "execute"
		}
		command := fmt.Sprintf("curl -q -H 'X-Probe: %d' -sSi 'https://example.test/a?id=1'", i)
		if tool == "execute" {
			command = "export PYTHONUNBUFFERED=1\n" + command
		}
		takeRepeatSlot(t, ctx, tool, map[string]interface{}{"command": command})
	}
	args := map[string]interface{}{"command": "curl --request=GET --url 'https://example.test/a?id=1'"}
	if _, err := AcquireHTTPRepeatGuard(ctx, "exec", args); err == nil {
		t.Fatal("sixth same URL/method must fail regardless of results")
	}
	for _, command := range []string{
		"curl -XPOST 'https://example.test/a?id=1'",
		"curl -I 'https://example.test/a?id=1'",
		"curl 'https://example.test/a?id=2'",
		"curl 'https://example.test/b?id=1'",
		"curl 'https://other.test/a?id=1'",
	} {
		takeRepeatSlot(t, ctx, "exec", map[string]interface{}{"command": command})
	}
	takeRepeatSlot(t, repeatGuardContext(t.Name()+"-other"), "exec", args)
	takeRepeatSlot(t, ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/a?id=1"})
}

func TestHTTPRepeatFrameworkURLAndContextIsolation(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	for i := 0; i < httpRepeatLimit; i++ {
		takeRepeatSlot(t, ctx, "external::http-framework-test", map[string]interface{}{
			"url": "https://example.test/a?nonce=1", "method": fmt.Sprint(i), "conversation_id": fmt.Sprint(i),
		})
	}
	args := map[string]interface{}{"url": "https://example.test/a?nonce=1", "conversation_id": "bypass"}
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", args); err == nil {
		t.Fatal("framework URL allowance must be independent of method and model-supplied session")
	}
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/new", "additional_args": "--ur https://other.test --repe 100"}); err == nil {
		t.Fatal("raw argv must not override the counted target or repeat allowance")
	}
	takeRepeatSlot(t, ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/a?nonce=2"})
	takeRepeatSlot(t, repeatGuardContext("different-context"), "http-framework-test", args)
	for i := 0; i < httpRepeatLimit+2; i++ {
		takeRepeatSlot(t, context.Background(), "http-framework-test", args)
	}
}

func TestHTTPRepeatConcurrentAdmission(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	var allowed atomic.Int32
	start, finish := make(chan struct{}), make(chan struct{})
	var entered, done sync.WaitGroup
	for i := 0; i < 64; i++ {
		entered.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			<-start
			release, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/a"})
			if err == nil {
				allowed.Add(1)
			}
			entered.Done()
			if err == nil {
				<-finish
				release()
			}
		}()
	}
	close(start)
	entered.Wait()
	close(finish)
	done.Wait()
	if got := allowed.Load(); got != httpRepeatLimit {
		t.Fatalf("concurrent allowed=%d, want exactly %d", got, httpRepeatLimit)
	}
}

func TestHTTPRepeatExpiryPinsInflightAndResetsHistory(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	now := time.Now()
	globalCommandRepeatRegistry.now = func() time.Time { return now }
	ctx := repeatGuardContext(t.Name())
	args := map[string]interface{}{"url": "https://example.test/a", "repeat": httpRepeatLimit}
	release, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", args)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(commandRepeatTTL + time.Second)
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", args); err == nil {
		t.Fatal("in-flight entries must not expire and restore allowance")
	}
	release()
	now = now.Add(commandRepeatTTL + time.Second)
	takeRepeatSlot(t, ctx, "http-framework-test", args)

	for i := 0; i < commandRepeatLimit; i++ {
		recordCommandRun(ctx, "echo test", "stable")
	}
	now = now.Add(commandRepeatTTL + time.Second)
	recordCommandRun(ctx, "echo test", "stable")
	if _, blocked := enforceCommandRepeatGuard(ctx, "echo test"); blocked {
		t.Fatal("expired result history was resurrected by a new result")
	}
}

func TestHTTPRepeatExpiresPerTargetWithoutClearingRecentTargets(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	now := time.Now()
	globalCommandRepeatRegistry.now = func() time.Time { return now }
	ctx := repeatGuardContext(t.Name())
	a := map[string]interface{}{"url": "https://example.test/a", "repeat": 5}
	b := map[string]interface{}{"url": "https://example.test/b", "repeat": 5}
	takeRepeatSlot(t, ctx, "http-framework-test", a)
	for i := 0; i < commandRepeatLimit; i++ {
		recordCommandRun(ctx, "echo old", "stable")
	}
	now = now.Add(commandRepeatTTL / 2)
	takeRepeatSlot(t, ctx, "http-framework-test", b)
	now = now.Add(commandRepeatTTL/2 + time.Second)
	takeRepeatSlot(t, ctx, "http-framework-test", a)
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", b); err == nil {
		t.Fatal("expiring one target cleared a newer target's allowance")
	}
	recordCommandRun(ctx, "echo old", "stable")
	if _, blocked := enforceCommandRepeatGuard(ctx, "echo old"); blocked {
		t.Fatal("per-command expiry did not reset stale stability samples")
	}
}

func TestHTTPRepeatCacheLimitsPreserveLiveAllowance(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	for i := 0; i < commandRepeatMaxEntries; i++ {
		takeRepeatSlot(t, ctx, "http-framework-test", map[string]interface{}{"url": fmt.Sprintf("https://example.test/%d", i), "repeat": 5})
	}
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/new"}); err == nil {
		t.Fatal("full target cache must not evict live counters")
	}
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/0"}); err == nil {
		t.Fatal("spent allowance was lost under cache pressure")
	}
	for i := 1; i < commandRepeatMaxSessions; i++ {
		takeRepeatSlot(t, repeatGuardContext(fmt.Sprint(i)), "http-framework-test", map[string]interface{}{"url": "https://example.test/a"})
	}
	if _, err := AcquireHTTPRepeatGuard(repeatGuardContext("overflow"), "http-framework-test", map[string]interface{}{"url": "https://example.test/a"}); err == nil {
		t.Fatal("session cache must be bounded")
	}
	if len(globalCommandRepeatRegistry.sessions) != commandRepeatMaxSessions {
		t.Fatal("session limit exceeded")
	}
}

func TestHTTPRepeatCurlParsingConservative(t *testing.T) {
	key := func(command string) string {
		t.Helper()
		requests := repeatCurlRequests(command)
		if len(requests) != 1 {
			t.Fatalf("expected one target for %q: %v", command, requests)
		}
		for key := range requests {
			return key
		}
		return ""
	}
	for _, pair := range [][2]string{
		{`curl -d 'x=1' https://example.test/a`, `curl -XPOST https://example.test/a`},
		{`curl -d '' https://example.test/a`, `curl -XPOST https://example.test/a`},
		{`curl -w '%{http_code}\n' https://example.test/a`, `curl https://example.test/a`},
		{`curl https://example.test/a &`, `curl https://example.test/a`},
		{"export PYTHONUNBUFFERED=1\ncurl https://example.test/a", `curl https://example.test/a`},
		{`curl --request=GET -d 'x=1' https://example.test/a`, `curl https://example.test/a`},
		{`curl -G -d 'id=1' https://example.test/a`, `curl 'https://example.test/a?id=1'`},
		{`curl -G --data-urlencode 'q=hello world' https://example.test/a`, `curl 'https://example.test/a?q=hello%20world'`},
		{`curl -T file https://example.test/a`, `curl -XPUT https://example.test/a`},
		{`curl -F x=y https://example.test/a`, `curl -XPOST https://example.test/a`},
		{`curl -I https://example.test/a`, `curl -XHEAD https://example.test/a`},
		{`curl -H 'Referer: https://other.test/' -x https://proxy.test/ https://example.test/a`, `curl https://example.test/a`},
	} {
		if key(pair[0]) != key(pair[1]) {
			t.Fatalf("same request was not recognized: %q / %q", pair[0], pair[1])
		}
	}
	for _, command := range []string{
		`echo 'curl https://example.test/a'`, `sh -c 'curl https://example.test/a'`,
		`curl "$URL"`, `curl -K config https://example.test/a`,
		`curl -G -d @file https://example.test/a`, `curl https://example.test/a | cat`,
		`curl 'https://example.test/[1-5]'`, `python3 -c 'print("curl https://example.test/a")'`,
	} {
		if got := repeatCurlRequests(command); len(got) != 0 {
			t.Fatalf("ambiguous command must not invent a target: %q", command)
		}
	}
	if key(`curl 'https://example.test/a?id=1&id=2'`) == key(`curl 'https://example.test/a?id=2&id=1'`) {
		t.Fatal("query order must not be erased")
	}
}

func TestHTTPRepeatMultiURLAdmissionIsAtomic(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	for i := 0; i < httpRepeatLimit; i++ {
		takeRepeatSlot(t, ctx, "exec", map[string]interface{}{"command": "curl https://example.test/a"})
	}
	if _, err := AcquireHTTPRepeatGuard(ctx, "exec", map[string]interface{}{"command": "curl https://example.test/new https://example.test/a"}); err == nil {
		t.Fatal("one exhausted target must block the entire command")
	}
	for i := 0; i < httpRepeatLimit; i++ {
		takeRepeatSlot(t, ctx, "execute", map[string]interface{}{"command": "curl https://example.test/new"})
	}
}
