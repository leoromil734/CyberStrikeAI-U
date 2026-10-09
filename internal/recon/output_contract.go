package recon

import "strings"

// NativeStdoutFormat describes only the scanner's declared stdout contract.
// Callers supply actual argv (or historical explicit flags), never YAML defaults
// recovered at replay time. Export-only flags do not declare stdout machine data.
func NativeStdoutFormat(tool string, argv []string) string {
	switch CanonicalTool(tool) {
	case "nmap":
		xml, outputs, mixed := "", 0, false
		for i := 0; i < len(argv); i++ {
			flag := argv[i]
			if len(flag) < 3 {
				continue
			}
			kind := flag[:3]
			if kind != "-oX" && kind != "-oA" && kind != "-oN" && kind != "-oG" && kind != "-oS" {
				continue
			}
			value := flag[3:]
			if value == "" && i+1 < len(argv) {
				i++
				value = argv[i]
			}
			if kind == "-oX" {
				xml = value
				outputs++
			} else if kind == "-oA" || value == "-" {
				mixed = true
			}
		}
		if xml == "-" && outputs == 1 && !mixed {
			return "xml"
		}
	case "nuclei":
		machine := false
		for _, flag := range argv {
			if !strings.HasPrefix(flag, "-") {
				continue
			}
			// goflags accepts the single/double dash forms of these aliases.
			flag = strings.TrimPrefix(flag, "-")
			switch flag {
			case "-jsonl", "-json", "-j", "-jsonl=true", "-json=true", "-j=true", "jsonl", "json", "j", "jsonl=true", "json=true", "j=true":
				machine = true
			case "-jsonl=false", "-json=false", "-j=false", "jsonl=false", "json=false", "j=false":
				machine = false
			}
		}
		if machine {
			return "jsonl"
		}
	case "oneforall":
		// fmt selects an export file. Stdout/stderr remain human logs.
		return "log"
	}
	return "text"
}
