package c2

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestManagerSaveResultBlobConfinesPath(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(nil, zap.NewNop(), filepath.Join(tmp, "c2store"))
	content := base64.StdEncoding.EncodeToString([]byte("result bytes"))

	got, err := mgr.saveResultBlob("t_safe123", content, "txt")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "c2store", "results", "t_safe123.txt")
	if got != want {
		t.Fatalf("path=%q want %q", got, want)
	}
	raw, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "result bytes" {
		t.Fatalf("content=%q", raw)
	}

	for _, taskID := range []string{
		"", ".", "..", "../owned", `..\owned`, "sub/owned", "sub\\owned",
		"C:owned", "task:stream", "task::$DATA", "task.with.dot", "task.",
		"-leading", "task name", "task\x00id", "task?", "task*", "task|id", strings.Repeat("a", 129),
	} {
		if _, err := mgr.saveResultBlob(taskID, content, ".txt"); err == nil {
			t.Fatalf("unsafe task ID %q accepted", taskID)
		}
	}
	for _, taskID := range []string{"123e4567-e89b-12d3-a456-426614174000", strings.Repeat("a", 128)} {
		if _, err := mgr.saveResultBlob(taskID, content, ".txt"); err != nil {
			t.Fatalf("safe task ID %q rejected: %v", taskID, err)
		}
	}
	outside := filepath.Join(tmp, "owned")
	if _, err := mgr.saveResultBlob("t_safe123", content, "./../../owned"); err == nil {
		t.Fatal("expected traversal suffix to be rejected")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside file exists or stat failed unexpectedly: %v", err)
	}
}

func TestUploadPathForTaskConfinesPath(t *testing.T) {
	tmp := t.TempDir()
	store := filepath.Join(tmp, "c2store")

	dir, got, err := uploadPathForTask(store, "t_safe123")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(store, "uploads"); dir != want {
		t.Fatalf("dir=%q want %q", dir, want)
	}
	if want := filepath.Join(store, "uploads", "t_safe123.bin"); got != want {
		t.Fatalf("path=%q want %q", got, want)
	}

	for _, taskID := range []string{"", ".", "..", "../owned", `..\owned`, "sub/owned", "sub\\owned", "task.with.dot", "-leading", "C:owned", "task:stream"} {
		if _, _, err := uploadPathForTask(store, taskID); err == nil {
			t.Fatalf("task_id %q unexpectedly accepted", taskID)
		}
	}
}

func TestNormalizeResultBlobSuffix(t *testing.T) {
	for _, suffix := range []string{"", "png", ".jpg", ".7z", ".safe_name-1"} {
		if _, err := normalizeResultBlobSuffix(suffix); err != nil {
			t.Fatalf("suffix %q rejected: %v", suffix, err)
		}
	}
	for _, suffix := range []string{".", "..", "../x", "./../../x", "/tmp/x", `..\x`, ".name.with.dot", ".toolong012345678901234567890123456789", ".bin:stream"} {
		if _, err := normalizeResultBlobSuffix(suffix); err == nil {
			t.Fatalf("suffix %q unexpectedly accepted", suffix)
		}
	}
}

func TestEnsurePathInDirRejectsEscape(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "results")
	for _, path := range []string{dir, filepath.Join(dir, "..", "owned"), dir + "-other" + string(filepath.Separator) + "owned"} {
		if err := ensurePathInDir(dir, path); err == nil {
			t.Fatal("path outside result directory accepted")
		}
	}
}
