package vulnquality

import "testing"

// Sanitized structural reproduction of a real rejected record. These are text
// fixtures only; neither validation nor tests execute requests or scripts.
const mixedDebugDisclosureEvidence = `原始 HTTP 请求与响应（curl 发出、服务端返回，逐字原文）：

请求 1：
GET /missing HTTP/2
Host: example.invalid
Accept: text/html

响应 1（响应头与正文，逐字）：
HTTP/2 404
content-type: text/html; charset=utf-8

<pre>DEBUG=True; URL configuration exposed</pre>

请求 2：
GET /settings-error HTTP/2
Host: example.invalid
Accept: text/html

响应 2：
HTTP/2 500
content-type: text/html; charset=utf-8

<pre>DATABASES: engine=mysql, host=db.example.invalid, password=[redacted]</pre>

完整可运行脚本（Python 3，依赖 requests）：
import requests
r = requests.get('https://example.invalid/settings-error')
print(r.status_code)
print(r.text)

该脚本的实际执行输出（终端逐字原文）：
500
<pre>DATABASES: engine=mysql, host=db.example.invalid, password=[redacted]</pre>
`

func TestValidateEvidencePOCAcceptsMixedHTTPAndScriptTranscript(t *testing.T) {
	if err := ValidateEvidencePOC(mixedDebugDisclosureEvidence); err != nil {
		t.Fatalf("complete HTTP exchanges and actual output were mistaken for script-only evidence: %v", err)
	}
}

func TestValidateEvidencePOCAcceptsAnnotatedOutputHeadings(t *testing.T) {
	for _, heading := range []string{
		"该脚本的实际执行输出（终端逐字原文）：",
		"本次实际输出（已脱敏）：",
		"实际执行输出：",
		"响应 1（响应头与正文，逐字）：",
		"输出 2：",
		"Response 2 (captured):",
		"### 实际输出（终端原文）：",
		"**实际输出：**",
		"**实际输出**：",
	} {
		t.Run(heading, func(t *testing.T) {
			evidence := pythonEvidenceFixture + "\n" + heading + "\n500\ndatabase_settings_exposed=true\n"
			if err := ValidateEvidencePOC(evidence); err != nil {
				t.Fatalf("annotated output heading rejected: %v", err)
			}
		})
	}
}

func TestAnnotatedOutputHeadingsDoNotReplaceActualOutput(t *testing.T) {
	for _, output := range []string{"", "脚本执行成功。", "vulnerability confirmed", "TODO: 补充输出", "fixture_out.txt"} {
		evidence := pythonEvidenceFixture + "\n该脚本的实际执行输出（终端逐字原文）：\n" + output + "\n"
		if err := ValidateEvidencePOC(evidence); err == nil {
			t.Errorf("non-evidence output accepted: %q", output)
		}
	}
	// A heading printed inside a fenced script is still code, never a result.
	evidence := "```python\n" + pythonEvidenceFixture + "print('''\n该脚本的实际执行输出（终端逐字原文）：\n500\ndatabase_settings_exposed=true\n''')\n```"
	if err := ValidateEvidencePOC(evidence); err == nil {
		t.Fatal("script string literal was promoted to captured output")
	}
}
