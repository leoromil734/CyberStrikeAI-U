package agentfinalizer

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestStoppedReportInlineEscapingAndCredentialMinimization(t *testing.T) {
	cases := []struct {
		name, input, want string
		absent            []string
	}{
		{"html", `<img src=x onerror=alert(1)>`, "&lt;img", []string{"<img", "<script"}},
		{"markdown", "![track](https://outside.invalid/pixel) **safe** `x` | ~x~", `\!\[track\]\(`, []string{"![track]", "**safe**", "`x`", "https://"}},
		{"url", "https://user:URL_SECRET@app.example.test/path?token=QUERY_SECRET#FRAGMENT_SECRET", "app.example.test/path", []string{"URL_SECRET", "QUERY_SECRET", "FRAGMENT_SECRET", "user:"}},
		{"userinfo", "user:PRIVATE_PASSWORD@app.example.test", "app.example.test", []string{"user:", "PRIVATE_PASSWORD"}},
		{"json credential", `finding {"password":"PASSWORD_SECRET"}`, "敏感字段已隐藏", []string{"PASSWORD_SECRET"}},
		{"header credential", "Authorization: Bearer AUTH_SECRET", "敏感字段已隐藏", []string{"AUTH_SECRET"}},
		{"cookie", "Cookie: session=COOKIE_SECRET", "敏感字段已隐藏", []string{"COOKIE_SECRET"}},
		{"bearer", "service Bearer AUTH_SECRET", "认证值已隐藏", []string{"AUTH_SECRET"}},
		{"pem", "note -----BEGIN PRIVATE KEY----- PEM_SECRET", "凭据内容已隐藏", []string{"PEM_SECRET"}},
		{"control", "hello\n\r\t# title\u202esuffix", `hello \# title suffix`, []string{"\n", "\r", "\u202e"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportInline(tc.input)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("missing %q in %q", tc.want, got)
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Fatalf("unsafe %q in %q", absent, got)
				}
			}
		})
	}
	if got := reportInline(strings.Repeat("字", 1000000)); utf8.RuneCountInString(got) != stoppedInlineRunes+1 || !utf8.ValidString(got) {
		t.Fatalf("inline bound is not rune safe: %d", utf8.RuneCountInString(got))
	}
}

func TestStoppedScopeDoesNotEchoUnknownOrOversizedConfiguration(t *testing.T) {
	for _, raw := range []string{`{PRIVATE_INVALID`, `{"password":"PRIVATE_PASSWORD"}`, `{"notes":"PRIVATE_NOTES"}`, strings.Repeat("PRIVATE_LONG", stoppedScopeReadLimit)} {
		var b strings.Builder
		writeStoppedScope(&b, raw)
		if strings.Contains(b.String(), "PRIVATE_") || !strings.Contains(b.String(), "无法完整核实") {
			t.Fatalf("raw configuration escaped the scope boundary: %s", b.String())
		}
	}
	var b strings.Builder
	writeStoppedScope(&b, `{"targets":["a","b","c","d","e","f","PRIVATE_OMITTED"],"exclude":["excluded.example.test"],"notes":"PRIVATE_NOTE"}`)
	if strings.Count(b.String(), "- 登记目标：") != stoppedScopeItemLimit+1 || !strings.Contains(b.String(), "其余 1 项未展开") || !strings.Contains(b.String(), "excluded.example.test") || strings.Contains(b.String(), "PRIVATE_") {
		t.Fatalf("scope not bounded: %s", b.String())
	}
}

func TestStoppedGapsSummarizeWithoutPromotingUnverifiedProse(t *testing.T) {
	checks := []string{
		"6/6 passed; 全部安全 PRIVATE_UNKNOWN",
		"endpoint_count must equal inventory count 31 PRIVATE_COUNT_SUFFIX",
		"recon/endpoint/run-a/users: endpoint still needs baseline and risk mapping PRIVATE_ENDPOINT",
		"original ingestion failed: execution:scan-1; password=PRIVATE_CREDENTIAL",
		"tool execution still queued or running",
		"model report: <img src=x onerror=alert(1)> 6/6 passed",
		"missing evidenced recon/source for fofa_search (required initial source)",
		"independent endpoint inventory group discovery-a123 has no matching ledger disposition",
	}
	var b strings.Builder
	writeStoppedGaps(&b, checks)
	for _, want := range []string{"8 条完整检查诊断", "声明计数", "端点基线", "recon/endpoint/run-a/users", "scan-1", "原始结果入库", "排队或运行中的工具", "候选报告尚未正式提交", reportInline("fofa_search"), "discovery-a123"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing specific gap %q: %s", want, b.String())
		}
	}
	for _, absent := range []string{"PRIVATE_", "6/6 passed", "全部安全", "<img", "endpoint_count"} {
		if strings.Contains(b.String(), absent) {
			t.Fatalf("unverified diagnostic copied: %q", absent)
		}
	}
}

func TestStoppedGapsAreBoundedAndUnknownIsNotZero(t *testing.T) {
	checks := make([]string, stoppedGapScanLimit+1)
	for i := range checks {
		checks[i] = strings.Repeat("PRIVATE_UNKNOWN ", 200)
	}
	checks[len(checks)-1] = "recon/endpoint/OUTSIDE_LIMIT/users: needs baseline"
	var b strings.Builder
	writeStoppedGaps(&b, checks)
	if strings.Contains(b.String(), "OUTSIDE_LIMIT") || strings.Contains(b.String(), "PRIVATE_") || !strings.Contains(b.String(), "当前仍为未完成") {
		t.Fatalf("unknown diagnostics misrepresented: %s", b.String())
	}
	b.Reset()
	writeStoppedGaps(&b, nil)
	if !strings.Contains(b.String(), "具体缺口无法核实") || !strings.Contains(b.String(), "不能把缺少诊断当作检查通过") {
		t.Fatalf("missing checks were mistaken for passed checks: %s", b.String())
	}
}

func TestStoppedSectionBoundKeepsFollowingSections(t *testing.T) {
	var b strings.Builder
	appendStoppedSection(&b, "## 工具\n\n- "+strings.Repeat("&lt;", 200)+"\n", 200)
	b.WriteString("## 覆盖进度\n仍未完成\n")
	if utf8.RuneCountInString(b.String()) > 220 || strings.Contains(b.String(), "&lt") || !strings.Contains(b.String(), "本节展示已达长度上限") || !strings.Contains(b.String(), "## 覆盖进度") {
		t.Fatalf("section clipping split an escape or lost a later section: %s", b.String())
	}
}

func TestStoppedTextBoundPreservesUTF8(t *testing.T) {
	for _, tc := range []struct {
		text string
		max  int
		want string
		cut  bool
	}{{"abc", 3, "abc", false}, {"abc", 2, "ab", true}, {"评估😀报告", 3, "评估😀", true}, {"", 1, "", false}, {"x", 0, "", true}} {
		got, cut := boundStoppedText(tc.text, tc.max)
		if got != tc.want || cut != tc.cut || !utf8.ValidString(got) {
			t.Fatalf("bad bound: %q, %t", got, cut)
		}
	}
}
