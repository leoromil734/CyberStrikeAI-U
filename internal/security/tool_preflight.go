package security

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cyberstrike-ai/internal/config"
)

type ToolPreflight struct {
	Tool           string   `json:"tool"`
	Command        string   `json:"command"`
	Available      bool     `json:"available"`
	RuntimeChecked bool     `json:"runtimeChecked"`
	Warnings       []string `json:"warnings,omitempty"`
	Error          string   `json:"error,omitempty"`
	HelpPreview    string   `json:"helpPreview,omitempty"`
}

// Only these well-known help entrypoints may be run. A recipe cannot turn a
// preflight into an arbitrary shell command or an unbounded scan.
var safeHelpEntrypoints = map[string][]string{
	"amass": {"enum", "-h"}, "subfinder": {"-h"}, "dnsx": {"-h"}, "httpx-pd": {"-h"},
	"naabu": {"-h"}, "nmap": {"-h"}, "nuclei": {"-h"}, "katana": {"-h"}, "jsapiscan": {"--help"}, "jsluice": {"--help"}, "csai-jsluice": {"--help"},
}

func PreflightTool(ctx context.Context, tool config.ToolConfig, runtimeCheck bool) ToolPreflight {
	r := ToolPreflight{Tool: tool.Name, Command: tool.Command}
	if strings.HasPrefix(tool.Command, "internal:") {
		r.Available = true
		return r
	}
	path, err := exec.LookPath(tool.Command)
	if err != nil {
		r.Error = "command_not_found"
		return r
	}
	r.Available = true
	if tool.Name == "jsluice" && strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".exe") == "csai-jsluice" {
		if _, err := exec.LookPath("jsluice"); err != nil {
			r.Available = false
			r.Error = "jsluice_dependency_not_found"
			return r
		}
	}
	seen := map[string]bool{}
	for _, p := range tool.Parameters {
		if seen[p.Name] {
			r.Warnings = append(r.Warnings, "duplicate parameter: "+p.Name)
		}
		seen[p.Name] = true
		switch p.Type {
		case "string", "bool", "boolean", "int", "integer", "number", "float", "double", "array", "object":
		default:
			r.Warnings = append(r.Warnings, "unknown parameter type: "+p.Name)
		}
		if p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum {
			r.Warnings = append(r.Warnings, "invalid numeric range: "+p.Name)
		}
	}
	if !runtimeCheck {
		return r
	}
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".exe")
	args, ok := safeHelpEntrypoints[base]
	if !ok {
		r.Warnings = append(r.Warnings, "runtime help unavailable for this command; not executed")
		return r
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, path, args...)
	_ = prepareShellCmdSession(cmd)
	// This collector is bounded; no result is treated as a target response.
	output, runErr := boundedHelpOutput(probeCtx, cmd)
	r.RuntimeChecked = true
	if probeCtx.Err() != nil {
		r.Error = "help_timeout"
		return r
	}
	if runErr != nil && strings.TrimSpace(output) == "" {
		r.Error = "help_failed"
		return r
	}
	if len(output) > 16000 {
		output = output[:16000]
	}
	r.HelpPreview = output
	for _, p := range tool.Parameters {
		if p.Flag == "" || p.Format == "stdin" {
			continue
		}
		pattern := regexp.MustCompile(`(?:^|[\s,])` + regexp.QuoteMeta(p.Flag) + `(?:[\s,=:\[\]]|$)`)
		if !pattern.MatchString(output) {
			r.Warnings = append(r.Warnings, "flag not present in this version's help: "+p.Flag+" ("+p.Name+")")
		}
	}
	return r
}

func (e *Executor) validateVersionSensitiveFlags(ctx context.Context, tool *config.ToolConfig, args []string) error {
	// Amass -noalts is a known version mismatch from real executions. Do not
	// reject other flags just because abbreviated help omits them.
	if tool.Name != "amass" {
		return nil
	}
	for _, arg := range args {
		if arg == "-noalts" || strings.HasPrefix(arg, "-noalts=") {
			r := PreflightTool(ctx, *tool, true)
			if r.RuntimeChecked && r.Error == "" && !strings.Contains(r.HelpPreview, "-noalts") {
				return &ParameterValidationError{Field: "additional_args", Expected: "flags supported by installed amass", Problem: "当前版本不支持 -noalts；请移除该参数，预检未触发目标扫描"}
			}
			if !r.Available {
				return fmt.Errorf("工具依赖不可用: %s", tool.Command)
			}
		}
	}
	return nil
}
