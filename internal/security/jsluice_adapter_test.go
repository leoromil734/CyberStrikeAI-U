package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"gopkg.in/yaml.v3"
)

func TestJSLuiceBundledAdapterOfflineContract(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "tools")
	var tool config.ToolConfig
	raw, err := os.ReadFile(filepath.Join(root, "jsluice.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = yaml.Unmarshal(raw, &tool); err != nil {
		t.Fatal(err)
	}
	if tool.Name != "jsluice" || !tool.Enabled || tool.Command != "/usr/local/bin/csai-jsluice" {
		t.Fatalf("bad adapter: %+v", tool)
	}
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{"file": "/fixture/app.js", "source_url": "https://example.test/app.js"})
	if len(args) == 0 || args[0] != "urls" {
		t.Fatalf("missing offline mode: %v", args)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" --file /fixture/app.js ", " --source-url https://example.test/app.js ", " --timeout 120 "} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q: %v", want, args)
		}
	}
	for _, p := range tool.Parameters {
		if p.Name == "additional_args" || p.Flag == "-p" || p.Flag == "-j" {
			t.Fatalf("guessed or unbounded flag: %+v", p)
		}
		if p.Name == "file" && (!p.ExistingFile || !p.Required) {
			t.Fatal("local file must be required and existing")
		}
	}
	for _, name := range []string{"jsluice", "csai-jsluice"} {
		if strings.Join(safeHelpEntrypoints[name], " ") != "--help" {
			t.Fatalf("unsafe help entrypoint %s", name)
		}
	}
	var legacy config.ToolConfig
	raw, err = os.ReadFile(filepath.Join(root, "jsapiscan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = yaml.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Enabled || legacy.Name != "jsapiscan" || legacy.Command != "/usr/local/bin/jsapiscan" {
		t.Fatal("legacy compatibility was deleted or enabled by default")
	}
}
