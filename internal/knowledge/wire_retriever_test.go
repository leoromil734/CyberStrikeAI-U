package knowledge

import "testing"

// miniMaxM3RewriteOutput 是真实抓到的一次改写模型输出（MiniMax-M3，默认 AI 通道）：
// 推理过程与空行混在正文里，Eino 默认按 "\n" 裸切分会产出空查询，令整次检索报「查询不能为空」。
const miniMaxM3RewriteOutput = `<think>The user wants me to create three different versions of the query "SSRF bypass cloud metadata".

Let me think about what "SSRF bypass cloud metadata" means:
- SSRF = Server-Side Request Forgery

Three different perspectives:

1. **Technical exploitation perspective** - Focus on specific techniques</think>

1. Server-side request forgery techniques to access cloud metadata services despite IP filtering restrictions
2. How to bypass SSRF protections targeting AWS EC2 metadata, Azure IMDS, and GCP metadata endpoints
3. Methods for circumventing URL validation and network restrictions in SSRF attacks against cloud instance metadata APIs`

func TestSanitizeRewriteQueriesDropsThinkBlocksAndBlankLines(t *testing.T) {
	got := sanitizeRewriteQueries(miniMaxM3RewriteOutput)
	want := []string{
		"Server-side request forgery techniques to access cloud metadata services despite IP filtering restrictions",
		"How to bypass SSRF protections targeting AWS EC2 metadata, Azure IMDS, and GCP metadata endpoints",
		"Methods for circumventing URL validation and network restrictions in SSRF attacks against cloud instance metadata APIs",
	}
	if len(got) != len(want) {
		t.Fatalf("变体数量不符：got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条不符：got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSanitizeRewriteQueriesStripsListMarkersAndHeaders(t *testing.T) {
	content := "Here are the queries:\n```\n- kerberos delegation abuse\n2、ADCS 证书模板提权\n*  NTLM relay coercion\n```"
	got := sanitizeRewriteQueries(content)
	want := []string{"kerberos delegation abuse", "ADCS 证书模板提权", "NTLM relay coercion"}
	if len(got) != len(want) {
		t.Fatalf("变体数量不符：got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条不符：got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSanitizeRewriteQueriesDeduplicates(t *testing.T) {
	got := sanitizeRewriteQueries("SSRF bypass\nssrf bypass\n\nSSRF bypass")
	if len(got) != 1 {
		t.Fatalf("应去重为 1 条，got %q", got)
	}
}

func TestSanitizeRewriteQueriesOnlyThinkingReturnsEmpty(t *testing.T) {
	// 只有推理块时返回空，调用方（newRewriteHandler）负责回退原始查询。
	got := sanitizeRewriteQueries("<think>只有思考，没有最终查询</think>")
	if len(got) != 0 {
		t.Fatalf("应返回空，got %q", got)
	}
	// 未闭合的推理块同样整段丢弃。
	got = sanitizeRewriteQueries("<think>未闭合的推理\n还有一行")
	if len(got) != 0 {
		t.Fatalf("未闭合推理块应返回空，got %q", got)
	}
}

func TestSanitizeRewriteQueriesKeepsPayloadLines(t *testing.T) {
	got := sanitizeRewriteQueries("1. 169.254.169.254 IMDS 访问\n2. --header \"X-Forwarded-For: 127.0.0.1\"")
	want := []string{"169.254.169.254 IMDS 访问", "--header \"X-Forwarded-For: 127.0.0.1\""}
	if len(got) != len(want) {
		t.Fatalf("变体数量不符：got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条不符：got %q want %q", i, got[i], want[i])
		}
	}
}
