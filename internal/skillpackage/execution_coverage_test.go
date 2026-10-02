package skillpackage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBundledExecutionCoverageReferencesStayAligned(t *testing.T) {
	root := bundledSkillsRoot(t)
	tests := []struct {
		path string
		want []string
	}{
		{"attack-surface-recon/references/comprehensive-recon.md", []string{
			"Hetzner、OVH、AWS、Azure", "cdn_status", "当前 IP 是边缘节点", "不扩供应商网段",
			"SSH、数据库、SMTP/IMAP/POP3", "每账号≤8", "grep -rnoHE", "grep -rnHE", "sourcesContent",
			"两路原件", "工具零结果也必须执行", "不得对**输入源码**使用 `head`", "缺口被处理或逐项 blocked",
		}},
		{"src-hunting/references/credential-stuffing.md", []string{"SSH", "SMTP/IMAP/POP3", "40 个候选组合", "5 分钟", "完整 `-L` × `-P`", "blocked"}},
		{"src-hunting/references/recon-methodology.md", []string{"Hetzner 等云/托管商不是 CDN", "Cloudflare/Akamai", "非 CDN IP 必须", "不扩供应商网段"}},
		{"src-hunting/references/js-reverse-guide.md", []string{"工具 + 命令双通道", "grep/rg", "不能只抽", "相对 URL", "raw/unique/incremental", "缺任一路证据"}},
		{"credential-stuffing/references/lite-wordlists.md", []string{"cyberstrike-lite", "2270", "manifest.json", "100 条", "候选", "8", "300秒", "不会自动启动扫描"}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(tt.path)))
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range tt.want {
				if !strings.Contains(string(raw), required) {
					t.Errorf("reference missing %q", required)
				}
			}
		})
	}
	_, manifest, body := readBundledSkill(t, root, "credential-stuffing")
	for _, keyword := range []string{"SSH", "数据库", "SMTP/IMAP/POP3", "简单弱口令"} {
		if !strings.Contains(manifest.Description, keyword) {
			t.Errorf("credential description missing routing keyword %q", keyword)
		}
	}
	for _, required := range []string{"8 次", "40 个候选组合", "5 分钟", "并发 **1**", "3 秒", "跨 Web、SSH、数据库、邮件累计", "默认对和失败对照都计入", "不读取信箱、不发信"} {
		if !strings.Contains(body, required) {
			t.Errorf("credential skill missing %q", required)
		}
	}
	if strings.Contains(body, "最多 20 个") {
		t.Fatal("a supplied identity list must not override the five-identity execution budget")
	}
}

func TestHydraDefaultsMatchSimpleCredentialBudget(t *testing.T) {
	path := filepath.Join(bundledSkillsRoot(t), "..", "tools", "hydra.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tool struct {
		Description string `yaml:"description"`
		Parameters  []struct {
			Name    string `yaml:"name"`
			Default any    `yaml:"default"`
		} `yaml:"parameters"`
	}
	if err := yaml.Unmarshal(raw, &tool); err != nil {
		t.Fatal(err)
	}
	defaults := make(map[string]any)
	for _, parameter := range tool.Parameters {
		defaults[parameter.Name] = parameter.Default
	}
	if defaults["tasks"] != 1 || defaults["attempt_interval"] != 3 || defaults["wait_between"] != 3 || defaults["stop_on_first"] != true {
		t.Fatalf("unexpected Hydra defaults: %#v", defaults)
	}
	if !strings.Contains(tool.Description, "禁止全量") || !strings.Contains(tool.Description, "外部计时/取消") {
		t.Fatal("Hydra guidance must limit candidate pairs and require an overall deadline")
	}
}
