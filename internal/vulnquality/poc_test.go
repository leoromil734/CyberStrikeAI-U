package vulnquality

import (
	"strings"
	"testing"
)

// 这些都是静态文本夹具；验证器和测试均不会发请求或运行其中的脚本。
const httpEvidenceFixture = "GET /fixture?marker=fixture-marker HTTP/1.1\nHost: example.invalid\nAccept: application/json\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"marker\":\"fixture-marker\"}\n"

const pythonEvidenceFixture = "import requests\nr = requests.get('https://example.invalid/fixture', params={'marker': 'fixture-marker'})\nprint(r.status_code)\nprint(r.text)\n"

func TestValidateEvidencePOCRejectsNonReproducibleEvidence(t *testing.T) {
	response := "\n```http\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"marker\":\"fixture-marker\"}\n```"
	cases := map[string]string{
		"empty":                      " \t\n",
		"short":                      "存在漏洞",
		"narrative":                  strings.Repeat("已验证存在漏洞且成功执行，具有高风险，需要修复。", 5),
		"technical summary":          "GET /fixture 接口经过验证存在权限问题，HTTP/1.1 响应说明已绕过权限。计划用 curl 和 import requests 生成 payload，结果已确认成功。",
		"fake code fence":            "```python\n" + strings.Repeat("已确认漏洞可利用，但具体脚本稍后提供。", 5) + "\n```",
		"empty fence":                "```python\n\n```\n" + strings.Repeat("实际脚本与请求尚未粘贴。", 6),
		"unclosed fence":             "```python\n" + pythonEvidenceFixture + response,
		"script without output":      "```python\n" + pythonEvidenceFixture + "```",
		"fake output":                "```python\n" + pythonEvidenceFixture + "```\n```text\n脚本执行成功，已经验证漏洞存在且取得预期结果。\n```",
		"empty labeled output":       "```python\n" + pythonEvidenceFixture + "```\n实际输出：\n```text\n\n```",
		"placeholder labeled output": "```python\n" + pythonEvidenceFixture + "```\n实际输出：\n```text\nTODO: 补充原始输出\n```",
		"filename labeled output":    "```python\n" + pythonEvidenceFixture + "```\n实际输出：\n```text\nfixture_out.txt\n```",
		"script labeled as output":   "```python\n" + pythonEvidenceFixture + "```\n实际输出：\n```python\n" + pythonEvidenceFixture + "```",
		"filename instead of code":   "```sh\npython poc.py --target https://example.invalid/fixture\n```" + response,
		"result only":                response + "\n这是实际结果，但未记录触发请求和具体脚本。",
		"curl without URL":           "```sh\ncurl --data 'marker=fixture-marker'\n```" + response,
		"curl external body":         "```sh\ncurl --data-binary @payload.txt https://example.invalid/fixture\n```" + response,
		"curl external config":       "```sh\ncurl --config fixture.conf https://example.invalid/fixture\n```" + response,
		"request missing Host":       "```http\nGET /fixture HTTP/1.1\nAccept: application/json\n\n```" + response,
		"request missing blank":      "GET /fixture HTTP/1.1\nHost: example.invalid\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"marker\":\"fixture-marker\"}\n",
		"response missing blank":     "```http\nGET /fixture HTTP/1.1\nHost: example.invalid\n\n```\n```text\nHTTP/1.1 200 OK\n```",
		"placeholder script":         "```python\nimport requests\nr = requests.get('https://example.invalid/fixture')\n# TODO: 完整请求参数稍后补充\nprint(r.text)\n```" + response,
		"placeholder curl":           "```sh\ncurl https://example.invalid/fixture --data ...\n```" + response,
		"stdout inside script":       "```python\nimport requests\nr = requests.get('https://example.invalid/fixture')\nprint('uid=0(fixture) gid=0(fixture)')\n```",
		"protocol without target":    "C: USER fixture\nS: 331 Password required\nC: PASS fixture-password\nS: 230 Logged in\n",
		"OOB result only":            "2026-10-01T10:00:01Z query=fixture.example.invalid type=A source=192.0.2.1\n观察到了 DNSLog 回连，但没有粘贴触发输入。",
		"unrelated OOB":              "curl 'https://example.invalid/fixture?callback=other.example.invalid'\n2026-10-01T10:00:01Z query=observed.example.invalid type=A source=192.0.2.1\n",
	}
	for name, evidence := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateEvidencePOC(evidence); err == nil {
				t.Fatal("incomplete or narrative evidence should be rejected")
			}
			if HasValidPOC(evidence) {
				t.Fatal("HasValidPOC must use the same rejection rules")
			}
		})
	}
}

func TestValidateEvidencePOCAcceptsReproducibleEvidenceWithoutRequiringPython(t *testing.T) {
	cases := map[string]string{
		"raw HTTP":           httpEvidenceFixture,
		"fenced HTTP":        "```http\n" + httpEvidenceFixture + "```",
		"CRLF HTTP":          strings.ReplaceAll(httpEvidenceFixture, "\n", "\r\n"),
		"tilde fence":        "~~~http\n" + httpEvidenceFixture + "~~~",
		"long fence":         "````http\n" + httpEvidenceFixture + "````",
		"curl transcript":    "```sh\ncurl -i 'https://example.invalid/fixture?marker=fixture-marker'\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"marker\":\"fixture-marker\"}\n```",
		"multiline curl":     "```sh\ncurl --request GET \\\n  'https://example.invalid/fixture?marker=fixture-marker'\n```\n```json\n{\"marker\":\"fixture-marker\"}\n```",
		"python with stdout": "```python\n" + pythonEvidenceFixture + "```\n实际输出：\n```text\nstatus=200\n{\"marker\":\"fixture-marker\"}\n```",
		"unfenced python":    pythonEvidenceFixture + "Output:\n{\"marker\":\"fixture-marker\"}\n",
		"JavaScript":         "```javascript\nconst response = await fetch('https://example.invalid/fixture?marker=fixture-marker');\nconsole.log(await response.json());\n```\n```json\n{\"marker\":\"fixture-marker\"}\n```",
		"browser":            "浏览器页面：https://example.invalid/fixture\n```javascript\nconst element = document.querySelector('#fixture');\nconsole.log(JSON.stringify({marker: element.textContent}));\n```\n控制台：\n```json\n{\"marker\":\"fixture-marker\"}\n```",
		"protocol":           "目标：ftp://example.invalid:21\nC: USER fixture\nS: 331 Password required\nC: PASS fixture-password\nS: 230 Logged in\n",
		"OOB raw":            "```http\nGET /fixture?callback=fixture.example.invalid HTTP/1.1\nHost: example.invalid\n\n```\n```text\n2026-10-01T10:00:01Z query=fixture.example.invalid type=A source=192.0.2.1\n```",
		"OOB same segment":   "curl 'https://example.invalid/fixture?callback=fixture.example.invalid'\n2026-10-01T10:00:01Z query=fixture.example.invalid type=A source=192.0.2.1\n",
		"command transcript": "$ printf '%s' fixture-marker\nOutput:\n{\"marker\":\"fixture-marker\"}\n",
	}
	for name, evidence := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateEvidencePOC(evidence); err != nil {
				t.Fatalf("complete original input and output should pass: %v", err)
			}
			if !HasValidPOC(evidence) {
				t.Fatal("HasValidPOC must use the same acceptance rules")
			}
		})
	}
}

func TestValidateEvidencePOCRejectsTruncatedSQLWrite(t *testing.T) {
	truncated := "受控写入（fixture_out.txt）\n```sql\nINSERT INTO fixture(...) VALUES('fixture-marker',...);\nnew_id inserted_rows\n1 1\n```"
	if err := ValidateEvidencePOC(truncated); err == nil || !strings.Contains(err.Error(), "SQL") {
		t.Fatalf("truncated INSERT should be rejected with a SQL-specific reason: %v", err)
	}
}

func TestValidateEvidencePOCRejectsFilenameOnlyWrite(t *testing.T) {
	filenameOnly := "已完成受控写入，证据见 fixture_poc.py 和 fixture_out.txt，已确认成功写入一行，但原始输出与脚本未贴入记录。"
	if err := ValidateEvidencePOC(filenameOnly); err == nil || !strings.Contains(err.Error(), "文件") {
		t.Fatalf("filename-only write should be rejected: %v", err)
	}
}

func TestValidateEvidencePOCAcceptsCompleteWriteAndEmbeddedLongFile(t *testing.T) {
	complete := "```python\nimport sqlite3\nconn = sqlite3.connect(':memory:')\ncur = conn.cursor()\ncur.execute(\"CREATE TABLE fixture (id INTEGER PRIMARY KEY, marker TEXT)\")\ncur.execute(\"INSERT INTO fixture(marker) VALUES ('fixture-marker')\")\nconn.commit()\nprint('new_id', cur.lastrowid, 'inserted_rows', cur.rowcount)\ncur.execute(\"SELECT id, marker FROM fixture\")\nprint(cur.fetchall())\n```\n```text\nINSERT INTO fixture(marker) VALUES ('fixture-marker');\nnew_id inserted_rows\n1 1\nid marker\n1 fixture-marker\n```"
	if err := ValidateEvidencePOC(complete); err != nil {
		t.Fatalf("complete write+script should pass: %v", err)
	}
	// 文件名可以作为完整内联内容的标签，而不能作为替代；大文件不应受旧的 1200 字符邻域限制。
	longEmbedded := "fixture_poc.py 完整内联内容：\n```python\n" + strings.Repeat("# fixture comment\n", 100) + pythonEvidenceFixture + "```\n```json\n{\"marker\":\"fixture-marker\"}\n```"
	if err := ValidateEvidencePOC(longEmbedded); err != nil {
		t.Fatalf("long embedded script should not be mistaken for a filename-only reference: %v", err)
	}
}
