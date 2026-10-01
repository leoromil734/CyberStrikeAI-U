package vulnquality

import "testing"

// Complete PoCs may print normal stdout rather than JSON or HTTP headers.
// These fixtures are text only: none of the example requests are executed.
func TestValidateEvidencePOCOrdinaryStdout(t *testing.T) {
	cases := map[string]string{
		"python plain stdout":   "```python\nimport requests\nr = requests.get('https://example.invalid/fixture')\nprint(r.status_code)\nprint(r.text)\n```\n实际输出：\n```text\n200\nfixture-marker\n```",
		"curl status and size":  "```sh\ncurl -s -o /dev/null -w '%{http_code} %{size_download}\\n' 'https://example.invalid/fixture'\n```\n实际输出：\n```text\n200 1234\n```",
		"elapsed timing stdout": "```python\nimport time\nimport requests\nstart = time.monotonic()\nr = requests.get('https://example.invalid/fixture')\nprint('elapsed=' + str(time.monotonic() - start))\n```\n实际输出：\n```text\nelapsed=4.5\n```",
	}
	for name, evidence := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateEvidencePOC(evidence); err != nil {
				t.Fatalf("complete input with independent, explicitly labeled stdout must be accepted: %v", err)
			}
		})
	}
}

func TestValidateEvidencePOCRejectsLabeledSuccessAssertions(t *testing.T) {
	for _, output := range []string{"脚本执行成功。", "已验证存在漏洞。", "脚本执行成功，已经验证漏洞存在且取得预期结果。", "success", "vulnerability confirmed"} {
		evidence := "```python\nimport requests\nr = requests.get('https://example.invalid/fixture')\nprint(r.status_code)\n```\n实际输出：\n```text\n" + output + "\n```"
		if err := ValidateEvidencePOC(evidence); err == nil {
			t.Errorf("a labeled success assertion is still descriptive, not concrete output: %q", output)
		}
	}
}
