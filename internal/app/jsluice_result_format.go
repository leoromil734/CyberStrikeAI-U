package app

import (
	"path/filepath"
	"strings"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/recon"
)

func reconTool(name string) bool {
	switch recon.CanonicalTool(name) {
	case "fofa", "subfinder", "oneforall", "dnsx", "httpx", "naabu", "nmap", "gau", "katana", "jsapiscan", "jsluice", "nuclei":
		return true
	}
	return false
}

func trustedDirectScanner(args map[string]interface{}) string {
	command, _ := args["command"].(string)
	if command == "" || strings.ContainsAny(command, ";&|><`$\r\n") {
		return ""
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	name := filepath.Base(fields[0])
	if reconTool(name) {
		return recon.CanonicalTool(name)
	}
	return ""
}

func resultFormat(tool string, args map[string]interface{}) string {
	tool = recon.CanonicalTool(tool)
	fields := resultArgumentTokens(args)
	direct := trustedDirectScanner(args) != ""
	switch tool {
	case "fofa", "crtsh":
		return "json"
	case "jsapiscan", "jsluice", "oneforall":
		// Adapter stdout is a summary/log, never the private export original.
		return "log"
	case "nmap":
		// Legacy saved arguments were not tokenized by the executor. Preserve
		// the previously supported quoted stdout sentinel without sniffing data.
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-oX", "-oN", "-oG", "-oS":
				fields[i+1] = strings.Trim(fields[i+1], "\"'")
			}
		}
		if !direct {
			if xml, _ := args["xml_output"].(string); xml != "" {
				fields = append([]string{"-oX", xml}, fields...)
			}
		}
		return recon.NativeStdoutFormat(tool, fields)
	case "nuclei":
		if !direct && (args["json_output"] == true || args["jsonl"] == true) {
			fields = append([]string{"-jsonl"}, fields...)
		}
		return recon.NativeStdoutFormat(tool, fields)
	}
	if !direct {
		for _, key := range []string{"json", "json_output", "jsonl", "json_lines"} {
			if args[key] == true {
				return "jsonl"
			}
		}
	}
	for _, flag := range fields {
		if flag == "-json" || flag == "-jsonl" || flag == "-j" {
			return "jsonl"
		}
	}
	return "text"
}

func trustedInvocation(original *mcp.ToolExecution) *mcp.ToolInvocation {
	if original == nil || original.Invocation == nil || original.Invocation.Version != mcp.NativeCLIInvocationVersion || original.Invocation.ToolName != original.ToolName {
		return nil
	}
	return original.Invocation
}

func executionResultFormat(tool string, original *mcp.ToolExecution) string {
	if invocation := trustedInvocation(original); invocation != nil {
		switch recon.CanonicalTool(tool) {
		case "nmap", "nuclei":
			if invocation.StdoutFormat == "xml" || invocation.StdoutFormat == "jsonl" {
				// Only the separate stdout original is machine data. The display
				// copy may contain stderr, failure text and truncation wrappers.
				return "log"
			}
			return "text"
		}
	}
	return resultFormat(tool, original.Arguments)
}

// Only declared invocation options control legacy stdout format. No output
// sniffing, extension guessing, or inference from today's YAML defaults.
func resultArgumentTokens(args map[string]interface{}) []string {
	if command, ok := args["command"].(string); ok && trustedDirectScanner(args) != "" {
		return strings.Fields(command)
	}
	var fields []string
	for _, key := range []string{"scan_type", "additional_args"} {
		if value, ok := args[key].(string); ok {
			fields = append(fields, strings.Fields(value)...)
		}
	}
	return fields
}
