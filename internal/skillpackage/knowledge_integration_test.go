package skillpackage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type integrationSource struct {
	Repository       string `json:"repository"`
	Commit           string `json:"commit"`
	License          string `json:"license"`
	LicenseFile      string `json:"license_file"`
	AuthorPermission string `json:"author_permission"`
}

type integrationItem struct {
	ID                string              `json:"id"`
	Capability        string              `json:"capability"`
	Decision          string              `json:"decision"`
	ExistingAnchor    string              `json:"existing_anchor"`
	SourcePaths       map[string][]string `json:"source_paths"`
	KnowledgeTarget   string              `json:"knowledge_target"`
	SkillReference    string              `json:"skill_reference"`
	RelatedReferences []string            `json:"related_references"`
	RetrievalQueries  []string            `json:"retrieval_queries"`
	ValidationCase    struct {
		Positive      string   `json:"positive"`
		Negative      string   `json:"negative"`
		RequiredTerms []string `json:"required_terms"`
	} `json:"validation_case"`
}

type integrationManifest struct {
	SchemaVersion   int                          `json:"schema_version"`
	Scope           string                       `json:"scope"`
	RetrievalStatus string                       `json:"retrieval_status"`
	Sources         map[string]integrationSource `json:"sources"`
	PreservedSkills []string                     `json:"preserved_skills"`
	NewSkills       []string                     `json:"new_skills"`
	Items           []integrationItem            `json:"items"`
	Covered         []struct {
		Capability     string `json:"capability"`
		ExistingAnchor string `json:"existing_anchor"`
		Reason         string `json:"reason"`
	} `json:"covered"`
	Nonadopt []struct {
		Capability string `json:"capability"`
		Reason     string `json:"reason"`
	} `json:"nonadopt"`
}

func loadIntegrationManifest(t *testing.T) (string, integrationManifest) {
	t.Helper()
	root := filepath.Dir(bundledSkillsRoot(t))
	raw := readBundledDocument(t, root, "docs/knowledge-skill-integration/manifest.json")
	var manifest integrationManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func integrationLocalDocument(t *testing.T, root, rel string) string {
	t.Helper()
	if rel == "" || strings.Contains(rel, "\\") || strings.Contains(rel, ":") || filepath.IsAbs(rel) || filepath.ToSlash(filepath.Clean(rel)) != rel || strings.HasPrefix(rel, "../") {
		t.Fatalf("invalid portable integration path %q", rel)
	}
	return readBundledDocument(t, root, rel)
}

func TestKnowledgeSkillIntegrationManifestHasOfflineSourcesAndCases(t *testing.T) {
	root, manifest := loadIntegrationManifest(t)
	if manifest.SchemaVersion != 1 || manifest.Scope != "knowledge-and-skills-only" || !strings.Contains(manifest.RetrievalStatus, "offline-fixture-only") {
		t.Fatal("integration scope or offline status changed")
	}
	if len(manifest.Items) != 31 || len(manifest.PreservedSkills) != 32 || len(manifest.NewSkills) != 4 {
		t.Fatalf("unexpected integration inventory: items=%d preserved=%d new=%d", len(manifest.Items), len(manifest.PreservedSkills), len(manifest.NewSkills))
	}
	commits := map[string]string{
		"strix":       "007ed1a94e7dbf7b096c81e5b0354533ce94e0db",
		"neurosploit": "5d4e7e0347219ceae22735ec6af3d8cdd0561ded",
		"darkmoon":    "cb0d9b83e745034c8bcff90daee9668b834d1508",
	}
	for key, commit := range commits {
		source := manifest.Sources[key]
		if source.Commit != commit || source.License == "" || !strings.HasPrefix(source.Repository, "https://github.com/") {
			t.Errorf("source %s is not pinned with license and repository", key)
		}
		text := integrationLocalDocument(t, root, source.LicenseFile)
		if len(text) < 1000 {
			t.Errorf("source %s has incomplete license", key)
		}
		if key == "darkmoon" {
			for _, section := range []string{"0. Definitions.", "5. Conveying Modified Source Versions.", "17. Interpretation of Sections 15 and 16.", "END OF TERMS AND CONDITIONS", "https://www.gnu.org/licenses/why-not-lgpl.html"} {
				if !strings.Contains(text, section) {
					t.Errorf("GPL license missing %q", section)
				}
			}
			if len(text) < 30000 {
				t.Error("GPL license must retain the full text")
			}
		}
		if key == "neurosploit" && !strings.Contains(text, "Copyright (c) 2026 Joas A Santos & Red Team Leaders") {
			t.Error("MIT copyright notice missing")
		}
	}
	if !strings.Contains(manifest.Sources["darkmoon"].AuthorPermission, "2026-10-01") {
		t.Error("Dark-Moon author permission is missing")
	}
	seenIDs, seenKnowledge := map[string]bool{}, map[string]bool{}
	linkedPath := regexp.MustCompile("(?m)(?:^|[\\s`(])((?:knowledge_base|skills|docs/knowledge-skill-integration)/[A-Za-z0-9._/-]+\\.(?:md|txt))")
	for _, item := range manifest.Items {
		t.Run(item.ID, func(t *testing.T) {
			if item.ID == "" || seenIDs[item.ID] || seenKnowledge[item.KnowledgeTarget] {
				t.Fatal("empty or duplicated item/knowledge target")
			}
			seenIDs[item.ID], seenKnowledge[item.KnowledgeTarget] = true, true
			if item.Capability == "" || (item.Decision != "new" && item.Decision != "enrich") || len(item.SourcePaths) == 0 {
				t.Fatal("missing capability, decision or source paths")
			}
			integrationLocalDocument(t, root, item.ExistingAnchor)
			knowledge := integrationLocalDocument(t, root, item.KnowledgeTarget)
			reference := integrationLocalDocument(t, root, item.SkillReference)
			if !strings.HasPrefix(item.KnowledgeTarget, "knowledge_base/") || !strings.HasPrefix(item.SkillReference, "skills/") || !strings.Contains(item.SkillReference, "/references/") {
				t.Error("item must provide both a knowledge target and a progressive reference")
			}
			if utf8.RuneCountInString(knowledge) < 800 || len(strings.Split(knowledge, "\n")) < 50 {
				t.Error("knowledge is only a stub")
			}
			if !strings.Contains(reference, item.KnowledgeTarget) {
				t.Error("reference does not link its full knowledge document")
			}
			for sourceKey, paths := range item.SourcePaths {
				source, ok := manifest.Sources[sourceKey]
				if !ok || len(paths) == 0 {
					t.Errorf("unknown/empty source %q", sourceKey)
					continue
				}
				// CI must not depend on ignored reference clones or execute them.
				for _, path := range paths {
					if path == "" || strings.Contains(path, "..") || strings.Contains(path, "\\") {
						t.Errorf("invalid upstream source path %q", path)
					}
				}
				if !strings.Contains(knowledge, source.Commit[:7]) {
					t.Errorf("knowledge missing pinned source %s", sourceKey)
				}
			}
			if item.ValidationCase.Positive == "" || item.ValidationCase.Negative == "" || len(item.ValidationCase.RequiredTerms) < 2 || len(item.RetrievalQueries) != 2 {
				t.Error("missing positive/negative case or bilingual retrieval fixture")
			}
			// These assertions protect document contracts, not runtime truth or recall.
			for _, term := range item.ValidationCase.RequiredTerms {
				if !strings.Contains(strings.ToLower(knowledge), strings.ToLower(term)) {
					t.Errorf("knowledge missing case contract term %q", term)
				}
			}
			for _, rel := range item.RelatedReferences {
				integrationLocalDocument(t, root, rel)
			}
			for _, document := range []string{knowledge, reference} {
				for _, match := range linkedPath.FindAllStringSubmatch(document, -1) {
					integrationLocalDocument(t, root, match[1])
				}
			}
		})
	}
	if len(manifest.Covered) < 5 || len(manifest.Nonadopt) < 4 {
		t.Fatal("deduplication or rejected strategies missing")
	}
	for _, item := range manifest.Covered {
		integrationLocalDocument(t, root, item.ExistingAnchor)
		if item.Capability == "" || item.Reason == "" {
			t.Error("covered item needs an evidence anchor and deduplication reason")
		}
	}
}

func TestIntegrationPreservesSkillsAndNewEntriesUseRegisteredTools(t *testing.T) {
	root, manifest := loadIntegrationManifest(t)
	skillsRoot := filepath.Join(root, "skills")
	knownTools := map[string]bool{}
	// Parse repository declarations rather than assuming external tool aliases.
	constants := readBundledDocument(t, root, "internal/mcp/builtin/constants.go")
	for _, match := range regexp.MustCompile(`Tool\w+\s*=\s*"([a-z][a-z0-9_-]+)"`).FindAllStringSubmatch(constants, -1) {
		knownTools[match[1]] = true
	}
	paths, err := filepath.Glob(filepath.Join(root, "tools", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var declaration struct {
			Name string `yaml:"name"`
		}
		if err := yaml.Unmarshal(raw, &declaration); err != nil {
			t.Fatal(err)
		}
		knownTools[declaration.Name] = true
	}
	for _, name := range manifest.PreservedSkills {
		readBundledSkill(t, skillsRoot, name)
	}
	_, _, router := readBundledSkill(t, skillsRoot, "pentest-agent-os")
	for _, name := range manifest.NewSkills {
		_, entry, body := readBundledSkill(t, skillsRoot, name)
		if !strings.Contains(entry.Description, "src-hunting") || !strings.Contains(router, "`"+name+"`") {
			t.Errorf("%s must defer SRC and be reachable from the router", name)
		}
		if count := utf8.RuneCountInString(body); count > 3000 {
			t.Errorf("%s entry too large: %d runes", name, count)
		}
		for _, tool := range append(strings.Fields(entry.AllowedTools), bundledToolTableNames(body)...) {
			if !knownTools[tool] {
				t.Errorf("%s declares unregistered repository tool %q", name, tool)
			}
		}
	}
}

func TestIntegrationKeepsConfirmationAndToolSemantics(t *testing.T) {
	root, _ := loadIntegrationManifest(t)
	for rel, terms := range map[string][]string{
		"skills/api-security-testing/references/contract-driven-testing.md":    {"spectral lint", "unresolved", "不自动授予"},
		"skills/pentest-verification/references/oob-provenance.md":             {"DNS", "不自动证明", "代访问", "最多 5 分钟"},
		"skills/pentest-verification/references/retest-lifecycle.md":           {"unverifiable", "不等于", "静态", "恢复"},
		"skills/component-vuln-intel/references/dependency-reachability.md":    {"not_imported 不等于安全", "grep 命中不等于调用图", "tentative"},
		"skills/source-aware-whitebox/references/package-executor-identity.md": {"npx --no", "404", "不注册争议包名"},
		"skills/src-hunting/references/routing-index.md":                       {"CORS", "勿开", "真实", "infra-control-plane-testing", "MCP审批"},
	} {
		body := readBundledDocument(t, root, rel)
		for _, term := range terms {
			if !strings.Contains(body, term) {
				t.Errorf("%s lost contract %q", rel, term)
			}
		}
	}
}
