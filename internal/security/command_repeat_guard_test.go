package security

import (
	"context"
	"strings"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func repeatGuardContext(conversationID string) context.Context {
	return mcp.WithMCPConversationID(context.Background(), conversationID)
}

func resetCommandRepeatRegistryForTest() {
	globalCommandRepeatRegistry = &commandRepeatRegistry{sessions: make(map[string]*commandRepeatRecord)}
}

// 达到阈值且结果稳定时必须拦截，避免同一条探测命令无限空转。
func TestCommandRepeatGuardBlocksStableRepeats(t *testing.T) {
	resetCommandRepeatRegistryForTest()
	ctx := repeatGuardContext("conv-stable")
	cmd := "curl -q -sSi --max-time 25 'https://example.test/wp-json/litespeed/v1/check_ip'"

	for i := 0; i < commandRepeatLimit; i++ {
		if reject, blocked := enforceCommandRepeatGuard(ctx, cmd); blocked {
			t.Fatalf("run %d blocked before reaching the limit: %s", i+1, reject)
		}
		recordCommandRun(ctx, cmd, "HTTP/2 404 \r\nserver: nginx\r\n")
	}
	reject, blocked := enforceCommandRepeatGuard(ctx, cmd)
	if !blocked {
		t.Fatal("stable repeated command was not blocked")
	}
	for _, want := range []string{"已重复执行", "query_recon_inventory", "尚未测试的高价值 URL"} {
		if !strings.Contains(reject, want) {
			t.Fatalf("rejection lost guidance %q: %s", want, reject)
		}
	}
}

// 结果多变的命令不得被拦截：爬取/枚举类输出每次不同，重复执行是真实工作。
func TestCommandRepeatGuardAllowsUnstableOutput(t *testing.T) {
	resetCommandRepeatRegistryForTest()
	ctx := repeatGuardContext("conv-unstable")
	cmd := "curl -q -sSi 'https://example.test/api/items?page=1'"

	for i := 0; i < commandRepeatLimit+3; i++ {
		if reject, blocked := enforceCommandRepeatGuard(ctx, cmd); blocked {
			t.Fatalf("changing output wrongly blocked at run %d: %s", i+1, reject)
		}
		recordCommandRun(ctx, cmd, "item-"+string(rune('a'+i))+"-payload")
	}
}

// 不同会话之间必须互相独立：一条命令在 A 会话被拦不影响 B 会话。
func TestCommandRepeatGuardIsolatesConversations(t *testing.T) {
	resetCommandRepeatRegistryForTest()
	cmd := "curl -q -sSi 'https://example.test/admin'"

	blockedCtx := repeatGuardContext("conv-a")
	for i := 0; i < commandRepeatLimit; i++ {
		recordCommandRun(blockedCtx, cmd, "HTTP/2 401 \r\n")
	}
	if _, blocked := enforceCommandRepeatGuard(blockedCtx, cmd); !blocked {
		t.Fatal("first conversation should be blocked")
	}
	if reject, blocked := enforceCommandRepeatGuard(repeatGuardContext("conv-b"), cmd); blocked {
		t.Fatalf("second conversation wrongly blocked: %s", reject)
	}
}

// 归一化：仅空白差异视为同一条命令。
func TestCommandFingerprintNormalizesWhitespace(t *testing.T) {
	a := commandFingerprintOf("curl   -q  -sSi 'https://example.test/x'")
	b := commandFingerprintOf("curl -q -sSi 'https://example.test/x'")
	if a != b {
		t.Fatalf("whitespace-only difference produced different fingerprints: %s vs %s", a, b)
	}
	c := commandFingerprintOf("curl -q -sSi 'https://example.test/y'")
	if a == c {
		t.Fatal("different targets must not share a fingerprint")
	}
}

// 无会话上下文时不得拦截：单次调用与无归属执行路径保持原行为。
func TestCommandRepeatGuardSkipsWithoutConversation(t *testing.T) {
	resetCommandRepeatRegistryForTest()
	ctx := context.Background()
	cmd := "curl -q -sSi 'https://example.test/'"
	for i := 0; i < commandRepeatLimit+2; i++ {
		recordCommandRun(ctx, cmd, "HTTP/2 200 OK")
		if reject, blocked := enforceCommandRepeatGuard(ctx, cmd); blocked {
			t.Fatalf("unscoped execution wrongly blocked: %s", reject)
		}
	}
}

func TestItoaCoversSignedRange(t *testing.T) {
	for _, c := range []struct {
		in   int
		want string
	}{{0, "0"}, {7, "7"}, {10, "10"}, {12345, "12345"}, {-42, "-42"}} {
		if got := itoa(c.in); got != c.want {
			t.Fatalf("itoa(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}