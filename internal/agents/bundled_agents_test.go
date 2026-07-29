package agents

import (
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
