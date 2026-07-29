package skillpackage

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

var skillReferencePattern = regexp.MustCompile(`references/[A-Za-z0-9._/-]+\.md`)

func bundledSkillsRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "skills"))
}

func readBundledSkill(t *testing.T, root, name string) ([]byte, *SkillManifest, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, name, "SKILL.md"))
	if err != nil {
		t.Fatalf("read skill %s: %v", name, err)
	}
	manifest, body, err := ParseSkillMD(raw)
	if err != nil {
		t.Fatalf("parse skill %s: %v", name, err)
	}
	return raw, manifest, body
}

func TestBundledSkillsPassOfficialValidation(t *testing.T) {
	root := bundledSkillsRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	validated := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillPath := filepath.Join(root, entry.Name(), "SKILL.md")
		raw, err := os.ReadFile(skillPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Errorf("read %s: %v", skillPath, err)
			continue
		}
		if err := ValidateSkillMDPackage(raw, entry.Name()); err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
		}
		validated++
	}
	if validated < 25 {
		t.Fatalf("validated only %d bundled skills", validated)
	}
}

func TestBundledSkillReferencePathsExist(t *testing.T) {
	root := bundledSkillsRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, entry.Name(), "SKILL.md"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Errorf("read %s: %v", entry.Name(), err)
			continue
		}
		for _, reference := range skillReferencePattern.FindAllString(string(raw), -1) {
			path := filepath.Join(root, entry.Name(), filepath.FromSlash(reference))
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("%s references missing %s: %v", entry.Name(), reference, err)
				continue
			}
			if info.IsDir() {
				t.Errorf("%s reference is a directory: %s", entry.Name(), reference)
			}
		}
	}
}

func TestSkillDescriptionsDiscriminateRoutingScenarios(t *testing.T) {
	root := bundledSkillsRoot(t)
	tests := []struct {
		name     string
		keywords []string
	}{
		{"pentest-scan-quick", []string{"快速", "quick", "不适合宣称完整覆盖"}},
		{"pentest-scan-standard", []string{"默认", "standard", "Web/API"}},
		{"pentest-scan-deep", []string{"深度", "源码", "不表示无限扫描"}},
		{"source-aware-whitebox", []string{"源码", "动态 PoC", "不把静态命中直接当漏洞"}},
		{"api-security-testing", []string{"API", "BOLA", "缺少可达基线"}},
		{"web-attack-methods", []string{"Web", "API/BOLA", "不应"}},
		{"cdn-tls-fingerprint", []string{"浏览器", "CDN", "不要触发"}},
	}
	for _, tt := range tests {
		_, manifest, _ := readBundledSkill(t, root, tt.name)
		for _, keyword := range tt.keywords {
			if !strings.Contains(manifest.Description, keyword) {
				t.Errorf("%s description missing routing keyword %q", tt.name, keyword)
			}
		}
	}
}

func TestSkillRouterDefinesDistinctMinimalScenarioSets(t *testing.T) {
	root := bundledSkillsRoot(t)
	_, _, router := readBundledSkill(t, root, "pentest-agent-os")

	skillPattern := regexp.MustCompile("`([a-z0-9-]+)`")
	routes := make(map[string][]string)
	for _, line := range strings.Split(router, "\n") {
		cells := strings.Split(strings.TrimSpace(line), "|")
		if len(cells) != 5 {
			continue
		}
		routeMatch := skillPattern.FindStringSubmatch(cells[1])
		if len(routeMatch) != 2 {
			continue
		}
		for _, skillMatch := range skillPattern.FindAllStringSubmatch(cells[3], -1) {
			routes[routeMatch[1]] = append(routes[routeMatch[1]], skillMatch[1])
		}
	}

	want := map[string][]string{
		"quick-baseline": {"pentest-scan-quick", "attack-surface-recon", "pentest-verification"},
		"whitebox-code":  {"pentest-scan-standard", "source-aware-whitebox", "pentest-verification"},
		"api-bola":       {"pentest-scan-standard", "api-security-testing", "pentest-verification"},
		"edge-cdn":       {"pentest-scan-standard", "cdn-tls-fingerprint", "pentest-verification"},
	}
	seenSets := make(map[string]string, len(want))
	for route, expected := range want {
		got := routes[route]
		if strings.Join(got, ",") != strings.Join(expected, ",") {
			t.Errorf("route %s skills = %v, want %v", route, got, expected)
			continue
		}
		if len(got) != 3 {
			t.Errorf("route %s loads %d skills, want exactly 3", route, len(got))
		}
		signature := strings.Join(got, ",")
		if other, duplicate := seenSets[signature]; duplicate {
			t.Errorf("routes %s and %s use the same skill set", route, other)
		}
		seenSets[signature] = route
	}
}

func TestDeepAssessmentSkillsRequireCoverageAndContinuation(t *testing.T) {
	root := bundledSkillsRoot(t)

	_, _, recon := readBundledSkill(t, root, "attack-surface-recon")
	for _, required := range []string{
		"subfinder` + `oneforall",
		"`dnsx`",
		"逐文件提取 API base",
		"全面/Deep 侦察只有在以下账本",
	} {
		if !strings.Contains(recon, required) {
			t.Errorf("attack-surface-recon missing deep coverage rule %q", required)
		}
	}

	comprehensive, err := os.ReadFile(filepath.Join(root, "attack-surface-recon", "references", "comprehensive-recon.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"phase_ledger",
		"queued → fetched → analyzed → expanded",
		"discovered → extracted → baselined → risk-mapped",
		"账号 A/可行账号 B",
		"不能生成最终渗透总结",
	} {
		if !strings.Contains(string(comprehensive), required) {
			t.Errorf("comprehensive recon reference missing %q", required)
		}
	}

	_, _, deep := readBundledSkill(t, root, "pentest-scan-deep")
	for _, required := range []string{
		"高价值 `gap` 仍存在时不得结案",
		"未创建可行测试身份",
		"尚未展开 JS 路由表",
		"“下一步建议”",
	} {
		if !strings.Contains(deep, required) {
			t.Errorf("pentest-scan-deep missing exit gate %q", required)
		}
	}

	_, _, router := readBundledSkill(t, root, "pentest-agent-os")
	for _, required := range []string{
		"phase_ledger",
		"discovered → extracted → baselined → risk-mapped",
		"只能输出进度更新",
	} {
		if !strings.Contains(router, required) {
			t.Errorf("pentest-agent-os missing phase routing rule %q", required)
		}
	}
}

func TestProgressiveSkillEntryBudgets(t *testing.T) {
	root := bundledSkillsRoot(t)
	entrySkills := []string{
		"pentest-agent-os",
		"attack-surface-recon",
		"web-attack-methods",
		"api-security-testing",
		"pentest-verification",
		"pentest-blackboard",
	}
	for _, name := range entrySkills {
		_, _, body := readBundledSkill(t, root, name)
		if got := utf8.RuneCountInString(body); got > 3000 {
			t.Errorf("%s entry body too large: %d runes", name, got)
		}
	}

	_, _, router := readBundledSkill(t, root, "pentest-agent-os")
	for _, expected := range []string{"一个扫描模式", "一个领域 Skill", "一个验证 Skill", "pentest-scan-standard"} {
		if !strings.Contains(router, expected) {
			t.Errorf("pentest-agent-os missing minimal routing rule %q", expected)
		}
	}
}
