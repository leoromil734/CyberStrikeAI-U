package knowledge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// Exercises only local directory/database scanning. It does not construct an
// embedder, start an index job, call a model, or use ignored reference clones.
func TestIntegratedKnowledgeScanPreservesCategoriesAndQueuesOnlyChanges(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "docs", "knowledge-skill-integration", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Items []struct {
			KnowledgeTarget string `json:"knowledge_target"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Items) != 31 {
		t.Fatalf("unexpected integration inventory: %d", len(manifest.Items))
	}
	temp := t.TempDir()
	base := filepath.Join(temp, "knowledge")
	expected := map[string]string{}
	for _, item := range manifest.Items {
		if !strings.HasPrefix(item.KnowledgeTarget, "knowledge_base/") || strings.Contains(item.KnowledgeTarget, "..") {
			t.Fatalf("invalid knowledge path %q", item.KnowledgeTarget)
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.KnowledgeTarget)))
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(item.KnowledgeTarget, "knowledge_base/")
		path := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		expected[path] = string(content)
	}
	db, err := database.NewKnowledgeDB(filepath.Join(temp, "scan.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	manager := NewManager(db, base, zap.NewNop())
	ids, err := manager.ScanKnowledgeBase()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != len(expected) {
		t.Fatalf("new knowledge ids=%d, want %d", len(ids), len(expected))
	}
	rows, err := db.Query("SELECT id, category, title, file_path, content FROM knowledge_base_items")
	if err != nil {
		t.Fatal(err)
	}
	idByPath := map[string]string{}
	for rows.Next() {
		var id, category, title, path, content string
		if err := rows.Scan(&id, &category, &title, &path, &content); err != nil {
			t.Fatal(err)
		}
		original, found := expected[path]
		if !found || content != original {
			t.Errorf("unknown or incomplete knowledge %q", path)
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.Split(rel, string(filepath.Separator))[0]; category != want {
			t.Errorf("category=%q, want %q", category, want)
		}
		if want := strings.TrimSuffix(filepath.Base(path), ".md"); title != want {
			t.Errorf("title=%q, want %q", title, want)
		}
		idByPath[path] = id
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(idByPath) != len(expected) {
		t.Fatal("knowledge rows duplicated or omitted")
	}
	unchanged, err := manager.ScanKnowledgeBase()
	if err != nil || len(unchanged) != 0 {
		t.Fatalf("unchanged scan queued ids=%v, err=%v", unchanged, err)
	}
	first := manifest.Items[0].KnowledgeTarget
	changedPath := filepath.Join(base, filepath.FromSlash(strings.TrimPrefix(first, "knowledge_base/")))
	changedContent := expected[changedPath] + "\n离线回归标记：内容更新需要重新索引。\n"
	if err := os.WriteFile(changedPath, []byte(changedContent), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := manager.ScanKnowledgeBase()
	if err != nil || len(changed) != 1 || changed[0] != idByPath[changedPath] {
		t.Fatalf("content change queued ids=%v, err=%v", changed, err)
	}
	var count int
	var stored string
	if err := db.QueryRow("SELECT COUNT(*) FROM knowledge_base_items").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT content FROM knowledge_base_items WHERE id = ?", changed[0]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if count != len(expected) || stored != changedContent {
		t.Fatal("updated scan duplicated a row or lost content")
	}
}
