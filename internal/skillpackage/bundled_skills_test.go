package skillpackage

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
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
		{"src-hunting", []string{"SRC", "漏洞赏金", "挖某集团", "帮我测这个站", "JS 逆向找接口", "0day", "routing-index", "web-attack-methods"}},
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

func TestCompetingSkillDescriptionsDeferExplicitSrcContext(t *testing.T) {
	root := bundledSkillsRoot(t)
	for _, name := range []string{
		"web-attack-methods",
		"api-security-testing",
		"source-aware-whitebox",
		"attack-surface-recon",
		"recon-osint-playbook",
		"pentest-output-standards",
	} {
		_, manifest, _ := readBundledSkill(t, root, name)
		if !strings.Contains(manifest.Description, "src-hunting") {
			t.Errorf("%s description must defer explicit SRC context to src-hunting", name)
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
		"recon-osint":    {"pentest-scan-standard", "recon-osint-playbook", "attack-surface-recon", "pentest-verification"},
		"quick-baseline": {"pentest-scan-quick", "attack-surface-recon", "pentest-verification"},
		"whitebox-code":  {"pentest-scan-standard", "source-aware-whitebox", "pentest-verification"},
		"api-bola":       {"pentest-scan-standard", "api-security-testing", "pentest-verification"},
		"src-hunt":       {"pentest-scan-standard", "src-hunting", "pentest-verification"},
		"web-inject":     {"pentest-scan-standard", "web-attack-methods", "pentest-verification"},
		"edge-cdn":       {"pentest-scan-standard", "cdn-tls-fingerprint", "pentest-verification"},
		"cloud-k8s":      {"pentest-scan-standard", "cloud-attack-methods", "pentest-verification"},
		"ad-domain":      {"pentest-scan-standard", "active-directory-attack", "pentest-verification"},
		"post-ex":        {"pentest-scan-standard", "post-exploitation", "pentest-verification"},
		"llm-agent":      {"pentest-scan-standard", "ai-llm-app-attack", "pentest-verification"},
	}
	seenSets := make(map[string]string, len(want))
	for route, expected := range want {
		got := routes[route]
		if strings.Join(got, ",") != strings.Join(expected, ",") {
			t.Errorf("route %s skills = %v, want %v", route, got, expected)
			continue
		}
		if len(got) != len(expected) {
			t.Errorf("route %s loads %d skills, want exactly %d", route, len(got), len(expected))
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
		"jsapiscan",
		"recon-fact-schema.md",
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
		"jsapiscan",
		"recon/endpoint/*",
	} {
		if !strings.Contains(string(comprehensive), required) {
			t.Errorf("comprehensive recon reference missing %q", required)
		}
	}

	schema, err := os.ReadFile(filepath.Join(root, "attack-surface-recon", "references", "recon-fact-schema.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"recon/source/",
		"raw",
		"unique",
		"incremental",
		"alt_tried",
		"recon/endpoint/",
		"runtime_status",
	} {
		if !strings.Contains(string(schema), required) {
			t.Errorf("recon-fact-schema missing %q", required)
		}
	}

	_, _, deep := readBundledSkill(t, root, "pentest-scan-deep")
	for _, required := range []string{
		"高价值 `gap` 仍存在时不得结案",
		"未创建可行测试身份",
		"尚未展开 JS 路由表",
		"“下一步建议”",
		"recon/source/subfinder/*",
		"jsapiscan",
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
		"src-hunting",
		"pentest-verification",
		"pentest-blackboard",
	}
	for _, name := range entrySkills {
		_, _, body := readBundledSkill(t, root, name)
		got := utf8.RuneCountInString(body)
		t.Logf("%s entry body: %d runes", name, got)
		if got > 3000 {
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

func TestSrcHuntingSkillWiresRulesAndKnowledge(t *testing.T) {
	root := bundledSkillsRoot(t)
	_, _, body := readBundledSkill(t, root, "src-hunting")
	for _, required := range []string{
		"references/routing-index.md",
		"references/打穿短表.md",
		"references/rules/dig-scope-workflow.md",
		"references/rules/src-value-hunting.md",
		"references/rules/vuln-report-format.md",
		"fofa_search",
		"CORS",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("src-hunting missing %q", required)
		}
	}
	for _, rel := range []string{
		filepath.Join("src-hunting", "references", "routing-index.md"),
		filepath.Join("src-hunting", "references", "打穿短表.md"),
		filepath.Join("src-hunting", "references", "idor-test.md"),
		filepath.Join("src-hunting", "references", "rules", "vuln-report-format.md"),
		filepath.Join("src-hunting", "references", "rules", "dig-scope-workflow.md"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
}

// Only the dedicated MCP tool table is a tool-name declaration. Commands,
// fenced examples and general knowledge references are deliberately excluded.
func bundledToolTableNames(body string) []string {
	pattern := regexp.MustCompile("`([a-z][a-z0-9_-]*)`")
	var names []string
	inTools, inFence := false, false
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if strings.HasPrefix(line, "#") {
			inTools = strings.Contains(line, "系统工具补全")
			continue
		}
		if !inTools || !strings.HasPrefix(line, "|") {
			continue
		}
		for _, match := range pattern.FindAllStringSubmatch(line, -1) {
			names = append(names, match[1])
		}
	}
	return names
}

func readBundledDocument(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

func TestBundledToolTableNamesExcludeCommandsAndKnowledge(t *testing.T) {
	body := "## 知识手册\n| OOB | `interactsh` |\n" +
		"## 系统工具补全（场景 → MCP）\n| HTTP | `httpx` | `jsluice` |\n" +
		"| OOB | `interactsh-client` | `interactsh-client -json` |\n" +
		"```sh\n| command | `interactsh` |\n```\n" +
		"~~~sh\n| example | `interactsh` |\n~~~\n" +
		"通用知识里的 `interactsh` 不是工具声明。\n" +
		"## 示例\n| command | `interactsh` |\n"
	got := strings.Join(bundledToolTableNames(body), ",")
	if want := "httpx,jsluice,interactsh-client"; got != want {
		t.Fatalf("tool names = %q, want %q", got, want)
	}
}

func TestBundledOOBToolDeclarationsUseRegisteredName(t *testing.T) {
	root := bundledSkillsRoot(t)
	projectRoot := filepath.Dir(root)
	// The filename is interactsh.yaml, but name (not filename or command) is
	// the registered tool identifier used by skills, roles and agents.
	for file, want := range map[string]string{"interactsh.yaml": "interactsh-client", "jsluice.yaml": "jsluice", "jsapiscan.yaml": "jsapiscan"} {
		var tool struct {
			Name string `yaml:"name"`
		}
		raw := readBundledDocument(t, projectRoot, "tools/"+file)
		if err := yaml.Unmarshal([]byte(raw), &tool); err != nil {
			t.Fatal(err)
		}
		if tool.Name != want {
			t.Errorf("%s registered name = %q, want %q", file, tool.Name, want)
		}
	}
	check := func(source string, tools []string) {
		t.Helper()
		for _, tool := range tools {
			if tool == "interactsh" {
				t.Errorf("%s declares obsolete tool alias %q; use interactsh-client", source, tool)
			}
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, entry.Name(), "SKILL.md")); os.IsNotExist(err) {
			continue
		}
		_, manifest, body := readBundledSkill(t, root, entry.Name())
		check(entry.Name()+" allowed-tools", strings.Fields(manifest.AllowedTools))
		check(entry.Name()+" MCP table", bundledToolTableNames(body))
	}
	for _, name := range []string{"src-hunting", "web-attack-methods", "api-security-testing", "cloud-attack-methods", "ai-llm-app-attack"} {
		_, manifest, body := readBundledSkill(t, root, name)
		for section, tools := range map[string][]string{
			"allowed-tools": strings.Fields(manifest.AllowedTools),
			"MCP table":     bundledToolTableNames(body),
		} {
			if !containsBundledTool(tools, "interactsh-client") {
				t.Errorf("%s %s missing interactsh-client", name, section)
			}
		}
	}
	for dir, extension := range map[string]string{"roles": "*.yaml", "agents": "*.md"} {
		paths, err := filepath.Glob(filepath.Join(projectRoot, dir, extension))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			raw := readBundledDocument(t, projectRoot, filepath.Join(dir, filepath.Base(path)))
			if dir == "agents" {
				if !strings.HasPrefix(raw, "---\n") {
					t.Fatalf("%s missing front matter", path)
				}
				end := strings.Index(raw[4:], "\n---\n")
				if end < 0 {
					t.Fatalf("%s has unclosed front matter", path)
				}
				raw = raw[4 : 4+end]
			}
			var declaration struct {
				Tools []string `yaml:"tools"`
			}
			if err := yaml.Unmarshal([]byte(raw), &declaration); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			check(path, declaration.Tools)
			if dir == "roles" && containsBundledTool([]string{"渗透测试.yaml", "Web应用扫描.yaml", "API安全测试.yaml", "综合漏洞扫描.yaml"}, filepath.Base(path)) {
				for _, want := range []string{"jsapiscan", "interactsh-client"} {
					if !containsBundledTool(declaration.Tools, want) {
						t.Errorf("%s missing workflow tool %q", path, want)
					}
				}
			}
		}
	}
}

func containsBundledTool(tools []string, name string) bool {
	for _, tool := range tools {
		if tool == name {
			return true
		}
	}
	return false
}

func TestSrcAndDeepShareBoundedIdentityPreparation(t *testing.T) {
	root := bundledSkillsRoot(t)
	dig := readBundledDocument(t, root, "src-hunting/references/rules/dig-scope-workflow.md")
	_, _, deep := readBundledSkill(t, root, "pentest-scan-deep")
	policy := func(body string) string {
		t.Helper()
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimPrefix(strings.TrimSpace(line), "- ")
			if strings.HasPrefix(line, "仅在当前授权范围明确允许正常自助注册时") {
				return line
			}
		}
		t.Fatal("missing shared identity preparation rule")
		return ""
	}
	srcPolicy, deepPolicy := policy(dig), policy(deep)
	if srcPolicy != deepPolicy {
		t.Error("SRC and Deep identity preparation rules differ")
	}
	for _, required := range []string{
		"受控邮箱/手机号", "A/B", "最多新建两个测试账号", "一次正常提交",
		"最多一次同条件重试", "最多 5 分钟", "用户更严格限制优先",
		"验证码", "滑块", "短信费用", "人工审批", "不破解挑战", "不无限注册",
		"保护用户现有账户", "不登出/注销/吊销", "不改密/改绑/触发找回",
		"只阻断依赖 A/B 的对应矩阵单元", "不标安全、否定或 N/A", "独立可执行单元",
	} {
		if !strings.Contains(srcPolicy, required) {
			t.Errorf("identity rule missing %q", required)
		}
	}
	for _, obsolete := range []string{"匿名这段 N/A", "匿名 N/A", "四件套整段 N/A", "过了立刻改回原值"} {
		if strings.Contains(dig, obsolete) {
			t.Errorf("SRC retains contradictory identity rule %q", obsolete)
		}
	}
}

func TestSrcWorkflowEvidenceAndQueueBoundaries(t *testing.T) {
	root := bundledSkillsRoot(t)
	checks := map[string][]string{
		"src-hunting/references/routing-index.md": {
			"source-aware-whitebox", "运行时对齐", "静态映射", "动态闭合",
			"新增入口/身份/版本", "重新映射", "入口 + 身份 + 方法 + 参数",
			"仅为该组合", "队首优先仅对 `ready`", "OOB/身份/异步", "`waiting`",
			"最多 5 分钟", "独立 `ready`", "转 `blocked`", "无回调不单独判否",
		},
		"src-hunting/references/rules/dig-scope-workflow.md": {
			"同皮只继承前端发现", "安全边界必须有部署自身证据", "负结果不跨部署继承",
			"产品升级改造中、系统繁忙或网络超时不属于认证证据，记 `blocked`",
			"一种子闭环", "禁止多种子一次搜完", "不主动 FOFA 出圈",
		},
		"src-hunting/references/rules/src-value-hunting.md": {
			"两类都否定仅否定当前假设", "真实存储授权、文件解析、异步处理能力",
			"只能上传或下载、读不到敏感文件也不能执行 → 不测", "不报、不升链",
		},
		"src-hunting/references/file-upload-test.md": {
			"负结果仅否定当前假设", "STS/预签名/对象 key", "存储授权",
			"文件解析", "异步处理", "最多 5 分钟", "独立 `ready`", "记 `blocked`",
			"只验证敏感文件、跨主体存储权限或执行等高影响", "不增加 payload 或攻击强度",
		},
		"pentest-scan-deep/SKILL.md": {
			"入口 + 身份 + 方法 + 参数", "仅关闭该组合", "新入口/身份/版本需重新映射",
			"队首优先仅对 `ready`", "`waiting`", "独立 `ready`", "到期转 `blocked`",
			"同皮只继承前端发现", "安全边界必须有部署自身证据", "不是认证安全",
		},
		"../roles/渗透测试.yaml": {
			"最多新建两个测试账号", "最多一次同条件重试", "最多 5 分钟", "不磨挑战、不无限注册",
			"用户现有账户", "身份不足只把依赖双主体的对应单元记 blocked", "不记安全/否定/N/A",
			"同皮只继承前端发现", "部署自身证据", "入口 + 身份 + 方法 + 参数", "新增入口/身份/版本重新映射",
		},
		"../roles/综合漏洞扫描.yaml": {
			"队首优先仅对 `ready`", "`waiting`", "独立 `ready`", "转 `blocked`", "无回调不单独判否",
			"缺前提", "不能建立第二身份只阻断依赖它的对应单元", "不记安全/否定/N/A",
			"入口 + 身份 + 方法 + 参数", "连续三次失败仅关闭该组合",
		},
		"../agents/penetration.md": {
			"最多新建两个测试账号", "最多一次同条件重试", "最多 5 分钟", "不磨挑战、不无限注册",
			"用户现有账户", "缺少第二身份只把依赖 A/B 的对应单元", "不记安全、否定或 N/A",
			"队首优先仅对 `ready`", "独立 `ready`", "转 `blocked`", "安全边界必须有部署自身证据",
		},
	}
	for rel, required := range checks {
		body := readBundledDocument(t, root, rel)
		for _, phrase := range required {
			if !strings.Contains(body, phrase) {
				t.Errorf("%s missing workflow boundary %q", rel, phrase)
			}
		}
	}
	value := readBundledDocument(t, root, "src-hunting/references/rules/src-value-hunting.md")
	if strings.Contains(value, "两枪都否定 → 不测、不升链") {
		t.Error("upload negative probes must not close all file-processing hypotheses")
	}
}

func TestSrcWorkflowPreservesLowValueExclusions(t *testing.T) {
	root := bundledSkillsRoot(t)
	value := readBundledDocument(t, root, "src-hunting/references/rules/src-value-hunting.md")
	for _, required := range []string{
		"禁止**挖 CORS", "只测能打到他人会话的", "只读到标题、摘要、昵称",
		"没有密钥、只有内部路径或配置项 → 不测", "只读到非敏感文件 → 不测",
		"不测 Cookie 属性", "不测只害自己的 CSRF", "没改钱、没改密、没接管 → 不测",
		"钱和审核没动 → 不测", "没打到别人余额 → 不测",
		"缺安全头、点击劫持、Cookie 缺 Secure/HttpOnly、证书过期、弱 TLS、缺 HSTS",
		"没带出会话的开放重定向", "只能上传或下载、读不到敏感文件也不能执行 → 不测",
	} {
		if !strings.Contains(value, required) {
			t.Errorf("SRC value policy lost exclusion %q", required)
		}
	}
}
