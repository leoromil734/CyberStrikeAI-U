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

func readJSAPIscanTool(t *testing.T) config.ToolConfig {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate bundled tool")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "tools", "jsapiscan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var tool config.ToolConfig
	if err := yaml.Unmarshal(raw, &tool); err != nil {
		t.Fatal(err)
	}
	return tool
}

func TestJSAPIscanBundledYAMLBuildsVerifiedCLI(t *testing.T) {
	tool := readJSAPIscanTool(t)
	if tool.Name != "jsapiscan" || tool.Command != "/usr/local/bin/jsapiscan" || !tool.Enabled {
		t.Fatalf("unexpected tool registration: %+v", tool)
	}
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{"target": "https://app.example.test"})
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" -u https://app.example.test ", " -ft 2 ", " -d 8 ", " -maxreq 1000 ", " -maxapi 200 ", " --total-timeout 300 ", " -o txt ", " -op scan.txt ", " -aget ", " -savejs ", " -tlsverify "} {
		if !strings.Contains(joined, required) {
			t.Errorf("CLI missing %q: %v", required, args)
		}
	}
	for _, rejected := range []string{" -api ", " -gorog ", " -extlink ", " -Ineedparms ", " --allow-post-retry "} {
		if strings.Contains(joined, rejected) {
			t.Errorf("default CLI unexpectedly includes %q: %v", rejected, args)
		}
	}
	for _, parameter := range tool.Parameters {
		if parameter.Name == "additional_args" || parameter.Flag == "-Ineedparms" {
			t.Errorf("unsupported/boundary-bypassing parameter: %+v", parameter)
		}
	}
}

func TestJSAPIscanFileAndHeaderAliasesUseExistingFileValidation(t *testing.T) {
	tool := readJSAPIscanTool(t)
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{"file": "targets.txt", "headers_file": "headers.txt"})
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" -f targets.txt ", " -header-file headers.txt "} {
		if !strings.Contains(joined, required) {
			t.Errorf("CLI missing %q: %v", required, args)
		}
	}
	for _, name := range []string{"targets_file", "header_file"} {
		found := false
		for _, parameter := range tool.Parameters {
			if parameter.Name == name {
				found = parameter.ExistingFile
			}
		}
		if !found {
			t.Errorf("%s must require an existing regular file", name)
		}
	}
}

func TestJSAPIscanPOSTFallbackRequiresExplicitFlags(t *testing.T) {
	tool := readJSAPIscanTool(t)
	executor, _ := setupTestExecutor(t)
	args := executor.buildCommandArgs(tool.Name, &tool, map[string]interface{}{
		"url": "https://app.example.test", "api_tests": true,
		"get_only": false, "allow_post_retry": true,
	})
	joined := " " + strings.Join(args, " ") + " "
	if !strings.Contains(joined, " -api ") || !strings.Contains(joined, " --allow-post-retry ") || strings.Contains(joined, " -aget ") {
		t.Fatalf("POST fallback flags are inconsistent: %v", args)
	}
}
