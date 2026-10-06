package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkdownAgentValidateActualContent(t *testing.T) {
	dir := t.TempDir()
	valid := "---\nid: worker-one\nname: 安全核验专员\nmax_iterations: 0\n---\n\nReview the supplied local fixture.\n"
	if err := validateMarkdownAgentWrite(dir, "worker-one.md", []byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"missing front matter": "Review the fixture.",
		"missing name":         "---\nid: worker-one\n---\nReview the fixture.",
		"invalid raw ID":       strings.Replace(valid, "worker-one", "../worker", 1),
		"invalid raw name":     strings.Replace(valid, "安全核验专员", "../worker", 1),
		"oversize ID":          strings.Replace(valid, "worker-one", strings.Repeat("x", 65), 1),
		"missing instruction":  "---\nid: worker-one\nname: Worker\n---\n\n",
		"negative iterations":  strings.Replace(valid, "max_iterations: 0", "max_iterations: -1", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMarkdownAgentWrite(dir, "worker-one.md", []byte(content)); err == nil {
				t.Fatal("unsafe or incomplete content accepted")
			}
		})
	}
}

func TestMarkdownAgentIDCannotShadowAnotherFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("---\nid: shared-worker\nname: Worker\n---\n\nReview a fixture.\n")
	if err := os.WriteFile(filepath.Join(dir, "existing.md"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMarkdownAgentWrite(dir, "new.md", content); err == nil {
		t.Fatal("duplicate ID in another file accepted")
	}
	if err := validateMarkdownAgentWrite(dir, "existing.md", content); err != nil {
		t.Fatalf("editing the same file must preserve its ID: %v", err)
	}
}

func TestMarkdownAgentOrchestratorFieldsValidated(t *testing.T) {
	dir := t.TempDir()
	for _, filename := range []string{"orchestrator.md", "orchestrator-plan-execute.md", "orchestrator-supervisor.md"} {
		content := "---\nid: root-reviewer\nname: Root reviewer\nmax_iterations: -1\n---\nReview a fixture.\n"
		if err := validateMarkdownAgentWrite(dir, filename, []byte(content)); err == nil {
			t.Errorf("negative raw iteration limit ignored for %s", filename)
		}
	}
}

func TestMarkdownAgentBundledDefinitionsRemainValid(t *testing.T) {
	dir := filepath.Join("..", "..", "agents")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateMarkdownAgentWrite(dir, entry.Name(), content); err != nil {
			t.Errorf("existing definition %s rejected: %v", entry.Name(), err)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no bundled definitions checked")
	}
}
