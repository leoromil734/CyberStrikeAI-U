package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func loadDiscoveryTool(t *testing.T, name string) *config.ToolConfig {
	t.Helper()
	tool, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tool.Name != name || tool.Command != name || !tool.Enabled {
		t.Fatalf("unexpected discovery tool registration: %+v", tool)
	}
	return tool
}

func requireDiscoveryFlag(t *testing.T, args []string, flag, value string) {
	t.Helper()
	idx := indexOf(args, flag)
	if idx < 0 || idx+1 >= len(args) || args[idx+1] != value {
		t.Errorf("expected %s %q in argv: %q", flag, value, args)
	}
}

func TestDirsearchBundledDefaultsBuildBoundedCLI(t *testing.T) {
	tool := loadDiscoveryTool(t, "dirsearch")
	executor, _ := setupTestExecutor(t)
	input := map[string]interface{}{"url": "https://example.test/"}
	if err := executor.validateToolParameterValues(tool, input); err != nil {
		t.Fatal(err)
	}
	args := executor.buildCommandArgs(tool.Name, tool, input)
	for flag, value := range map[string]string{
		"-u": "https://example.test/", "-e": "php,html,js,txt,xml,json", "-t": "20",
		"--max-rate": "50", "--timeout": "10", "--max-time": "300", "--max-recursion-depth": "2",
	} {
		requireDiscoveryFlag(t, args, flag, value)
	}
	for _, flag := range []string{"-w", "-r", "--force-extensions", "--exclude-sizes", "--exclude-text", "--exclude-regex", "--exclude-response", "-x", "--exclude-status"} {
		if indexOf(args, flag) >= 0 {
			t.Errorf("default scan unexpectedly enables %s: %q", flag, args)
		}
	}

	properties := executor.buildInputSchema(tool)["properties"].(map[string]interface{})
	for name, want := range map[string]int{"threads": 20, "rate_limit": 50, "timeout": 30, "max_time": 900, "max_recursion_depth": 2} {
		property := properties[name].(map[string]interface{})
		minimum, ok := numericParameter(property["minimum"])
		if property["type"] != "integer" || property["default"] != want || !ok || minimum != 1 {
			t.Errorf("schema must expose positive bounded default for %s: %#v", name, property)
		}
	}
}

func TestDirsearchCustomBoundsAndCatchAllFiltersRemainSingleArguments(t *testing.T) {
	tool := loadDiscoveryTool(t, "dirsearch")
	executor, _ := setupTestExecutor(t)
	input := map[string]interface{}{
		"url": "https://example.test/app/", "extensions": "html,json", "wordlist": "small wordlist.txt",
		"threads": 3, "rate_limit": 5, "timeout": 4, "max_time": 30,
		"recursive": true, "max_recursion_depth": 1, "force_extensions": true,
		"exclude_sizes": "1234B,4KB", "exclude_text": "Page not found",
		"exclude_regex": "(?i)not found|unknown path", "exclude_response": "__baseline_missing_7e3a",
		"additional_args": "--no-color",
	}
	if err := executor.validateToolParameterValues(tool, input); err != nil {
		t.Fatal(err)
	}
	args := executor.buildCommandArgs(tool.Name, tool, input)
	for flag, value := range map[string]string{
		"-u": "https://example.test/app/", "-e": "html,json", "-w": "small wordlist.txt",
		"-t": "3", "--max-rate": "5", "--timeout": "4", "--max-time": "30", "--max-recursion-depth": "1",
		"--exclude-sizes": "1234B,4KB", "--exclude-text": "Page not found",
		"--exclude-regex": "(?i)not found|unknown path", "--exclude-response": "__baseline_missing_7e3a",
	} {
		requireDiscoveryFlag(t, args, flag, value)
	}
	for _, flag := range []string{"-r", "--force-extensions", "--no-color"} {
		if indexOf(args, flag) < 0 {
			t.Errorf("explicit option %s missing: %q", flag, args)
		}
	}
}

func TestDirsearchBudgetsRejectUnlimitedAndInvalidValues(t *testing.T) {
	tool := loadDiscoveryTool(t, "dirsearch")
	executor, _ := setupTestExecutor(t)
	for _, name := range []string{"threads", "rate_limit", "timeout", "max_time", "max_recursion_depth"} {
		t.Run(name, func(t *testing.T) {
			for _, value := range []interface{}{0, -1, 1.5, false, "0"} {
				input := map[string]interface{}{"url": "https://example.test/", name: value}
				if err := executor.validateToolParameterValues(tool, input); err == nil {
					t.Errorf("unlimited/invalid %s value accepted: %#v", name, value)
				}
			}
		})
	}
}

func TestDirsearchWordlistUsesBundledDefaultOrVerifiedExplicitFile(t *testing.T) {
	tool := loadDiscoveryTool(t, "dirsearch")
	executor, _ := setupTestExecutor(t)
	input := map[string]interface{}{"url": "https://example.test/"}
	resolved, warnings, err := executor.resolveToolFileArgs(tool, input)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("omitted wordlist must retain dirsearch's bundled dictionary: %v %v", warnings, err)
	}
	if indexOf(executor.buildCommandArgs(tool.Name, tool, resolved), "-w") >= 0 {
		t.Fatal("omitted wordlist must not guess an installation-specific path")
	}

	path := filepath.Join(t.TempDir(), "small wordlist.txt")
	input["wordlist"] = path
	if _, _, err := executor.resolveToolFileArgs(tool, input); err == nil {
		t.Fatal("missing explicit wordlist must not silently change candidate sets")
	}
	if err := os.WriteFile(path, []byte("index.%EXT%\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolved, warnings, err = executor.resolveToolFileArgs(tool, input)
	if err != nil || len(warnings) != 0 || resolved["wordlist"] != path {
		t.Fatalf("explicit dictionary not preserved: %v %v %v", resolved, warnings, err)
	}
}

func TestFFufAlternativeScanKeepsFiniteRuntime(t *testing.T) {
	tool := loadDiscoveryTool(t, "ffuf")
	executor, _ := setupTestExecutor(t)
	input := map[string]interface{}{"url": "https://example.test/FUZZ"}
	requireDiscoveryFlag(t, executor.buildCommandArgs(tool.Name, tool, input), "-maxtime", "300")
	input["max_time"] = 30
	requireDiscoveryFlag(t, executor.buildCommandArgs(tool.Name, tool, input), "-maxtime", "30")
	input["max_time"] = 0
	if err := executor.validateToolParameterValues(tool, input); err == nil {
		t.Fatal("ffuf alternative must not silently remove the total runtime bound")
	}
	for _, text := range []string{tool.ShortDescription, tool.Description} {
		if !strings.Contains(text, "dirsearch") || !strings.Contains(text, "自定义请求") {
			t.Errorf("ffuf tool guidance lost discovery/fuzzing responsibilities: %s", text)
		}
	}
}
