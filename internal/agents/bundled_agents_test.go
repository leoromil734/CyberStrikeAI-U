package agents

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

func bundledAgentsRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "agents"))
}

func TestBundledAgentRolesStayFocusedAndWithinBudget(t *testing.T) {
	load, err := LoadMarkdownAgentsDir(bundledAgentsRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(load.FileEntries); got != 16 {
		t.Fatalf("loaded %d bundled agent roles, want 16", got)
	}

	sharedHeadings := []string{
		"## 范围与执行边界",
		"## 证据闭环",
		"## 独立安全边界",
		"## 执行与恢复",
		"## Skill 路由",
		"## 项目黑板与漏洞记录",
		"## 完成与交付",
	}
	seenIDs := make(map[string]string, len(load.FileEntries))
	for _, entry := range load.FileEntries {
		role := entry.Config
		if role.ID == "" || role.Description == "" || role.Instruction == "" {
			t.Errorf("%s must define id, description, and instruction", entry.Filename)
			continue
		}
		if previous, duplicate := seenIDs[role.ID]; duplicate {
			t.Errorf("%s and %s share role id %q", entry.Filename, previous, role.ID)
		}
		seenIDs[role.ID] = entry.Filename
		if got := utf8.RuneCountInString(role.Instruction); got > 4000 {
			t.Errorf("%s role instruction too large: %d runes", entry.Filename, got)
		}
		if !strings.Contains(role.Instruction, "## 独有职责") {
			t.Errorf("%s does not declare role-specific responsibilities", entry.Filename)
		}
		for _, heading := range sharedHeadings {
			if strings.Contains(role.Instruction, heading) {
				t.Errorf("%s repeats shared contract heading %q", entry.Filename, heading)
			}
		}
	}
}

func TestComprehensivePentestRolesCannotStopAfterRecon(t *testing.T) {
	load, err := LoadMarkdownAgentsDir(bundledAgentsRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	roles := make(map[string]string, len(load.FileEntries))
	for _, entry := range load.FileEntries {
		roles[entry.Config.ID] = entry.Config.Instruction
	}

	checks := map[string][]string{
		"recon": {
			"`subfinder`、`oneforall`、`dnsx`",
			"队列为空",
			"jsluice",
			"recon/source/",
			"不得** `record_vulnerability`",
			"不能因缺少现成账号跳过",
		},
		"attack-surface-enumeration": {
			"懒加载 chunk、worker 和 source map",
			"不能批量否定 JS 中的真实接口",
			"注册、激活、登录、找回和登出",
			"jsluice",
			"recon/endpoint/",
		},
		"penetration": {
			"创建最少测试账号",
			"两个独立测试主体",
			"Continuation Handoff",
			"不能生成最终总结",
		},
		"cyberstrike-deep": {
			"phase_ledger",
			"pending/active/passed/blocked",
			"侦察交接只是阶段产物",
			"recon/source/",
		},
		"cyberstrike-supervisor": {
			"phase_ledger",
			"不得把阶段摘要直接 `exit`",
		},
		"cyberstrike-plan-execute": {
			"phase_ledger",
			"不能在侦察步骤后直接安排最终报告",
		},
	}
	for id, required := range checks {
		instruction, ok := roles[id]
		if !ok {
			t.Errorf("missing bundled role %q", id)
			continue
		}
		for _, keyword := range required {
			if !strings.Contains(instruction, keyword) {
				t.Errorf("role %s missing comprehensive assessment guard %q", id, keyword)
			}
		}
	}

	roleYAML, err := os.ReadFile(filepath.Join(bundledAgentsRoot(t), "..", "roles", "渗透测试.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"subfinder`、`oneforall`、`dnsx",
		"phase_ledger",
		"递归清点 HTML、manifest、动态 chunk、worker 和 source map",
		"创建最少测试账号",
		"存在可执行 `gap/tentative` 时只能输出进度",
	} {
		if !strings.Contains(string(roleYAML), required) {
			t.Errorf("penetration role YAML missing %q", required)
		}
	}
}
