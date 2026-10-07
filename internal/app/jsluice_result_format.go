package app

import (
	"path/filepath"
	"strings"

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
	if name == "httpx-pd" {
		name = "httpx"
	}
	if reconTool(name) {
		return recon.CanonicalTool(name)
	}
	return ""
}

func resultFormat(tool string, args map[string]interface{}) string {
	tool = recon.CanonicalTool(tool)
	fields := resultArgumentTokens(args)
	switch tool {
	case "fofa", "crtsh":
		return "json"
	case "jsapiscan", "jsluice":
		// Adapter stdout is a summary, never the private JSONL/CSV original.
		return "log"
	case "nmap":
		xml, _ := args["xml_output"].(string)
		outputs := 0
		if xml != "" {
			outputs++
		}
		mixed := false
		for i, flag := range fields {
			value := ""
			if i+1 < len(fields) {
				value = strings.Trim(fields[i+1], "\"'")
			}
			if flag == "-oX" {
				xml = value
				outputs++
			}
			if strings.HasPrefix(flag, "-oX") && len(flag) > 3 {
				xml = flag[3:]
				outputs++
			}
			if strings.HasPrefix(flag, "-oA") {
				mixed = true
			}
			if (flag == "-oN" || flag == "-oG" || flag == "-oS") && value == "-" {
				mixed = true
			}
			if flag == "-oN-" || flag == "-oG-" || flag == "-oS-" {
				mixed = true
			}
		}
		if xml == "-" && outputs == 1 && !mixed {
			return "xml"
		}
		return "text"
	case "nuclei":
		machine := args["json_output"] == true || args["jsonl"] == true
		for _, flag := range fields {
			switch flag {
			case "-jsonl", "-json", "-j", "-jsonl=true", "-j=true":
				machine = true
			case "-jsonl=false", "-json=false", "-j=false":
				machine = false
			}
		}
		if machine {
			return "jsonl"
		}
		return "text"
	}
	for _, key := range []string{"json", "json_output", "jsonl", "json_lines"} {
		if args[key] == true {
			return "jsonl"
		}
	}
	for _, flag := range fields {
		if flag == "-json" || flag == "-jsonl" || flag == "-j" {
			return "jsonl"
		}
	}
	return "text"
}

// Only declared invocation options control stdout format. No output sniffing,
// extension guessing, or historical inference from today's YAML defaults.
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
