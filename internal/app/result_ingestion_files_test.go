package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/evidence"
)

func TestManagedOriginalRetryReusesIdenticalBytes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "execution")
	data := []byte("原件\x00\xff\n")
	if err := writeManagedOriginal(dir, "input.json", data); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(filepath.Join(dir, "input.json"))
	for i := 0; i < 3; i++ {
		if err := writeManagedOriginal(dir, "input.json", data); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.Stat(filepath.Join(dir, "input.json"))
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("retry replaced the original instead of verifying it")
	}
	for _, changed := range [][]byte{[]byte("short"), []byte("替件\x00\xff\n")} {
		if err := writeManagedOriginal(dir, "input.json", changed); !errors.Is(err, evidence.ErrChanged) {
			t.Fatalf("changed bytes accepted: %v", err)
		}
	}
	actual, _ := os.ReadFile(filepath.Join(dir, "input.json"))
	if string(actual) != string(data) {
		t.Fatal("mismatch overwrote saved original")
	}
	// Models a crash after input succeeded but before output was written.
	if err := writeManagedOriginal(dir, "output.txt", []byte("saved output")); err != nil {
		t.Fatal(err)
	}
}

func TestManagedOriginalRejectsSymlinksAndTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "../x", "sub/x", `sub\x`, ".", "..", "x:y", "x\x00y"} {
		if err := writeManagedOriginal(dir, name, nil); !errors.Is(err, evidence.ErrUnsafePath) {
			t.Fatalf("unsafe name %q accepted: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedOriginal(dir, "directory", nil); !errors.Is(err, evidence.ErrUnsafePath) {
		t.Fatalf("existing directory accepted: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink creation unavailable on this host: %v", err)
	}
	if err := writeManagedOriginal(dir, "link", []byte("same")); !errors.Is(err, evidence.ErrUnsafePath) {
		t.Fatalf("same-byte symlink accepted: %v", err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(filepath.Dir(target), alias); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedOriginal(alias, "new", nil); !errors.Is(err, evidence.ErrUnsafePath) {
		t.Fatalf("directory symlink accepted: %v", err)
	}
}

func TestManagedOriginalBindingCannotChange(t *testing.T) {
	dir := t.TempDir()
	first := []byte(`{"execution":"e","owner":"u","assessment":"a","scope":"s"}`)
	if err := writeManagedOriginal(dir, "binding.json", first); err != nil {
		t.Fatal(err)
	}
	if err := writeManagedOriginal(dir, "binding.json", []byte(`{"execution":"e","owner":"v","assessment":"a","scope":"s"}`)); !errors.Is(err, evidence.ErrChanged) {
		t.Fatalf("cross-owner binding reused: %v", err)
	}
}
