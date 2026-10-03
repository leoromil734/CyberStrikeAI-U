// tool-doctor validates declared recipes and optionally runs only allowlisted
// help entrypoints. It never starts a scan or requires a model/API credential.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/security"
	"gopkg.in/yaml.v3"
)

func main() {
	dir := flag.String("tools-dir", "tools", "recipe directory")
	runtimeCheck := flag.Bool("runtime", false, "probe allowlisted --help entrypoints, never targets")
	selected := flag.String("names", "", "optional comma-separated tool names")
	flag.Parse()
	allow := map[string]bool{}
	for _, name := range strings.Split(*selected, ",") {
		if name = strings.TrimSpace(name); name != "" {
			allow[name] = true
		}
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	failed := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(*dir, entry.Name()))
		if err != nil {
			failed = true
			continue
		}
		var tool config.ToolConfig
		if err := yaml.Unmarshal(data, &tool); err != nil {
			_ = encoder.Encode(map[string]string{"file": entry.Name(), "error": "invalid_yaml"})
			failed = true
			continue
		}
		if !tool.Enabled || (len(allow) > 0 && !allow[tool.Name]) {
			continue
		}
		report := security.PreflightTool(context.Background(), tool, *runtimeCheck)
		if report.Error != "" || len(report.Warnings) > 0 {
			failed = true
		}
		_ = encoder.Encode(report)
	}
	if failed {
		os.Exit(2)
	}
}
