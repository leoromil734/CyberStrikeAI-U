package config

import (
	"path/filepath"
	"testing"
)

func TestDiscoveryToolParameterContracts(t *testing.T) {
	for _, name := range []string{"dirsearch", "ffuf"} {
		t.Run(name, func(t *testing.T) {
			tool, err := LoadToolFromFile(filepath.Join("..", "..", "tools", name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if tool.Name != name || tool.Command != name || !tool.Enabled {
				t.Fatalf("unexpected tool registration: %+v", tool)
			}
			parameters := make(map[string]ParameterConfig)
			for _, parameter := range tool.Parameters {
				if _, exists := parameters[parameter.Name]; exists {
					t.Fatalf("duplicate parameter %s", parameter.Name)
				}
				parameters[parameter.Name] = parameter
			}
			maxTimeFlag := "--max-time"
			if name == "ffuf" {
				maxTimeFlag = "-maxtime"
			}
			type bound struct {
				flag  string
				value int
			}
			bounds := map[string]bound{"max_time": {maxTimeFlag, 900}}
			if name == "dirsearch" {
				bounds["threads"] = bound{"-t", 20}
				bounds["rate_limit"] = bound{"--max-rate", 50}
				bounds["timeout"] = bound{"--timeout", 30}
				bounds["max_recursion_depth"] = bound{"--max-recursion-depth", 2}
			}
			for key, want := range bounds {
				param, ok := parameters[key]
				if !ok || param.Type != "int" || param.Format != "flag" || param.Flag != want.flag || param.Default != want.value || param.Minimum == nil || *param.Minimum != 1 {
					t.Errorf("invalid bounded parameter %s: %+v", key, param)
				}
			}
			if name != "dirsearch" {
				return
			}
			for key, flag := range map[string]string{"recursive": "-r", "force_extensions": "--force-extensions"} {
				param := parameters[key]
				if param.Type != "bool" || param.Flag != flag || param.Default != false {
					t.Errorf("optional expansion must be explicitly enabled: %+v", param)
				}
			}
			for key, flag := range map[string]string{"exclude_sizes": "--exclude-sizes", "exclude_text": "--exclude-text", "exclude_regex": "--exclude-regex", "exclude_response": "--exclude-response"} {
				param := parameters[key]
				if param.Type != "string" || param.Format != "flag" || param.Flag != flag || param.Required || param.Default != nil {
					t.Errorf("catch-all filters require explicit observed values: %+v", param)
				}
			}
			wordlist := parameters["wordlist"]
			if wordlist.Required || !wordlist.ExistingFile || wordlist.Default != nil || len(wordlist.FallbackPaths) != 0 {
				t.Fatalf("dirsearch must preserve bundled dictionary and validate explicit files: %+v", wordlist)
			}
		})
	}
}
