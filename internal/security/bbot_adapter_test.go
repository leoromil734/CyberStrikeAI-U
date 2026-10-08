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

func readBBOTTool(t *testing.T) config.ToolConfig {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate bundled tool")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "tools", "bbot.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var tool config.ToolConfig
	if err := yaml.Unmarshal(raw, &tool); err != nil {
		t.Fatal(err)
	}
	return tool
}

func argIndex(args []string, want string) int {
	for i, arg := range args {
		if arg == want {
			return i
		}
	}
	return -1
}

// The recipe must delegate to the managed sandbox launcher; the launcher owns
// the BBOT home, output directory, non-interactive and no-dependency options.
func TestBBOTBundledYAMLTargetsManagedLauncher(t *testing.T) {
	tool := readBBOTTool(t)
	if tool.Name != "bbot" || tool.Command != "/usr/local/bin/csai-bbot" || !tool.Enabled {
		t.Fatalf("bbot recipe must be enabled and use the managed launcher: name=%s command=%s enabled=%v", tool.Name, tool.Command, tool.Enabled)
	}
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{"target": "example.com"})
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" -t example.com ", " -p subdomain-enum ", " --json "} {
		if !strings.Contains(joined, required) {
			t.Errorf("default CLI missing %q: %v", required, args)
		}
	}
	// Injected by the launcher after the sandbox already guarantees them.
	for _, managed := range []string{" --no-deps ", " -o ", " -y ", "--no-color"} {
		if strings.Contains(joined, managed) {
			t.Errorf("recipe must not bake launcher-managed option %q: %v", managed, args)
		}
	}
	if argIndex(args, "-c") != -1 {
		t.Errorf("recipe must not set BBOT config options by default: %v", args)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "home=") {
			t.Errorf("recipe must not set the BBOT home: %v", args)
		}
	}
}

func TestBBOTPresetListStaysOneTokenForLauncherExpansion(t *testing.T) {
	tool := readBBOTTool(t)
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{
		"target":        "example.com",
		"presets":       "subdomain-enum web",
		"require_flags": "passive",
		"brief":         true,
	})
	index := argIndex(args, "-p")
	if index < 0 || index+1 >= len(args) || args[index+1] != "subdomain-enum web" {
		t.Fatalf("preset list must stay a single token for the launcher to expand: %v", args)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" -rf passive ", " --brief "} {
		if !strings.Contains(joined, required) {
			t.Errorf("CLI missing %q: %v", required, args)
		}
	}
}

func TestBBOTBooleanAndOptionalFlagsAreExplicit(t *testing.T) {
	tool := readBBOTTool(t)
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{
		"target":      "example.com",
		"json_output": false,
		"dry_run":     true,
	})
	joined := " " + strings.Join(args, " ") + " "
	if strings.Contains(joined, " --json ") {
		t.Errorf("explicit json_output=false must drop --json: %v", args)
	}
	if !strings.Contains(joined, " --dry-run ") {
		t.Errorf("dry_run=true must add --dry-run: %v", args)
	}
	for _, optional := range []string{" -o ", " --event-types ", " -n "} {
		if strings.Contains(joined, optional) {
			t.Errorf("optional %q must stay unset by default: %v", optional, args)
		}
	}
}

func TestBBOTRecipeParametersAreShellFree(t *testing.T) {
	tool := readBBOTTool(t)
	additional := ""
	for _, parameter := range tool.Parameters {
		if parameter.Format == "stdin" {
			t.Errorf("bbot recipe must not use stdin parameters: %+v", parameter)
		}
		if parameter.Name == "additional_args" {
			additional = parameter.Format
			if parameter.Position != nil {
				t.Errorf("additional_args must stay a trailing append, not a numbered position: %+v", parameter)
			}
			continue
		}
		if parameter.Flag == "" {
			t.Errorf("parameter %s must map to an explicit flag", parameter.Name)
		}
		if strings.ContainsAny(parameter.Flag, ";|&`$\n") {
			t.Errorf("parameter %s has shell metacharacters in its flag: %q", parameter.Name, parameter.Flag)
		}
	}
	if additional != "positional" {
		t.Errorf("additional_args must keep the append format, got %q", additional)
	}
}
