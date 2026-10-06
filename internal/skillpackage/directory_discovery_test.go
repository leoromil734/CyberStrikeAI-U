package skillpackage

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDirectoryDiscoverySkillsDeclareBothTools(t *testing.T) {
	root := bundledSkillsRoot(t)
	for _, name := range []string{"attack-surface-recon", "src-hunting", "web-attack-methods", "pentest-scan-deep"} {
		t.Run(name, func(t *testing.T) {
			_, manifest, _ := readBundledSkill(t, root, name)
			for _, tool := range []string{"dirsearch", "ffuf"} {
				if !containsBundledTool(strings.Fields(manifest.AllowedTools), tool) {
					t.Errorf("skill omits discovery/fuzzing tool %q", tool)
				}
			}
		})
	}
}

func TestDirectoryDiscoverySkillGuidancePreservesCoverageAndReuse(t *testing.T) {
	root := bundledSkillsRoot(t)
	for _, name := range []string{"attack-surface-recon", "src-hunting", "web-attack-methods"} {
		t.Run(name, func(t *testing.T) {
			_, _, body := readBundledSkill(t, root, name)
			for _, required := range []string{"dirsearch", "ffuf", "未链接路径尚未覆盖", "有界目录发现", "复用", "仅爬取/JS 提取不算", "超时未完成留 gap/blocked"} {
				if !strings.Contains(body, required) {
					t.Errorf("discovery guidance missing %q", required)
				}
			}
		})
	}
}

func TestDirectoryDiscoveryRolesPreserveToolAccessAndAcceptanceCriteria(t *testing.T) {
	projectRoot := filepath.Dir(bundledSkillsRoot(t))
	for _, name := range []string{"Web应用扫描", "信息收集"} {
		t.Run(name, func(t *testing.T) {
			raw := readBundledDocument(t, projectRoot, "roles/"+name+".yaml")
			var role struct {
				Tools      []string `yaml:"tools"`
				UserPrompt string   `yaml:"user_prompt"`
			}
			if err := yaml.Unmarshal([]byte(raw), &role); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"dirsearch", "ffuf"} {
				if !containsBundledTool(role.Tools, tool) {
					t.Errorf("role filters out required discovery/fuzzing tool %s", tool)
				}
			}
			for _, required := range []string{
				"目录、文件和扩展名枚举优先 dirsearch", "参数、虚拟主机和自定义请求模糊测试优先 ffuf",
				"未链接路径尚未覆盖", "有界目录发现", "候选集", "证据可引用复用", "不重复扫描",
				"blocked/N/A", "随机路径基线", "停止原因", "仅爬取/JS 提取不算目录覆盖", "超时未完成留 gap/blocked",
			} {
				if !strings.Contains(role.UserPrompt, required) {
					t.Errorf("role discovery acceptance criteria missing %q", required)
				}
			}
		})
	}
}

func TestDirectoryDiscoveryReferencesDoNotEquateToolSuccessWithCoverage(t *testing.T) {
	root := bundledSkillsRoot(t)
	tests := []struct {
		path string
		want []string
	}{
		{"attack-surface-recon/references/comprehensive-recon.md", []string{
			"## 3.1", "未链接路径尚未覆盖", "单接口验证", "同一 origin", "认证态", "字典/扩展名及过滤条件",
			"execution_id", "ffuf", "不为调用次数", "不同部署", "catch-all", "exclude_response", "不是本地文件",
			"50 请求/秒", "总时限 900 秒", "429", "用户更严预算优先", "force_extensions", "hash/候选数",
			"covered", "完成所选候选集", "即使进程返回成功也不能写全覆盖", "not-applicable", "续跑只补剩余候选",
		}},
		{"attack-surface-recon/references/recon-fact-schema.md", []string{
			"完成所选候选集", "超时/限流/中断", "仅爬取/JS 提取不算目录覆盖", "同范围有效证据复用", "不把必须调用某个工具当覆盖证明",
		}},
		{"src-hunting/references/recon-methodology.md", []string{
			"目录、文件和扩展名枚举优先 `dirsearch`", "参数、虚拟主机和自定义请求模糊测试优先 `ffuf`",
			"引用复用", "仅爬取/JS 提取不算目录覆盖", "catch-all", "--max-rate 50 --timeout 10 --max-time 900",
			"超时/限流/中断未完成留 gap/blocked", "执行/原件引用",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			body := readBundledDocument(t, root, tt.path)
			for _, required := range tt.want {
				if !strings.Contains(body, required) {
					t.Errorf("directory coverage reference missing %q", required)
				}
			}
		})
	}
}

func TestDirectoryDiscoveryToolDescriptionsDoNotRestoreFFufAsDirectoryDefault(t *testing.T) {
	projectRoot := filepath.Dir(bundledSkillsRoot(t))
	for _, name := range []string{"dirsearch", "ffuf", "gobuster", "feroxbuster"} {
		t.Run(name, func(t *testing.T) {
			body := readBundledDocument(t, projectRoot, "tools/"+name+".yaml")
			for _, obsolete := range []string{"目录爆破主用仍是 `ffuf`", "Web 模糊/目录发现的**主用工具**", "目录发现也可配合 dirsearch"} {
				if strings.Contains(body, obsolete) {
					t.Errorf("tool description restores obsolete default: %s", obsolete)
				}
			}
		})
	}
}
