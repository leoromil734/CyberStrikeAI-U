package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

// This package has no scanner, database or cgo dependency. Keep this small
// contract regression runnable even when full executor integration cannot build.
func TestReconOutputRecipeContracts(t *testing.T) {
	for _, name := range []string{"nmap", "nuclei", "oneforall"} {
		t.Run(name, func(t *testing.T) {
			tool, err := LoadToolFromFile(filepath.Join("..", "..", "tools", name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if !tool.Enabled || tool.Command != name {
				t.Fatalf("unexpected registration: %+v", tool)
			}
			for _, code := range tool.AllowedExitCodes {
				if code != 0 {
					t.Fatalf("nonzero scanner exit must not become success: %d", code)
				}
			}
			params := map[string]ParameterConfig{}
			for _, parameter := range tool.Parameters {
				if _, exists := params[parameter.Name]; exists {
					t.Fatalf("duplicate parameter %s", parameter.Name)
				}
				params[parameter.Name] = parameter
			}
			switch name {
			case "nmap":
				if !reflect.DeepEqual(tool.Args, []string{"-sT", "-sV", "-sC"}) {
					t.Fatalf("XML must not be fixed args removed by scan_type: %#v", tool.Args)
				}
				p := params["xml_output"]
				if p.Type != "string" || p.Flag != "-oX" || p.Format != "flag" || p.Default != "-" || p.Required {
					t.Fatalf("invalid XML stdout/explicit file opt-out contract: %+v", p)
				}
			case "nuclei":
				for key, flag := range map[string]string{"json_output": "-jsonl", "silent": "-silent"} {
					p := params[key]
					if p.Type != "bool" || p.Flag != flag || p.Format != "flag" || p.Default != true || p.Required {
						t.Fatalf("invalid JSONL default/explicit false contract: %+v", p)
					}
				}
			case "oneforall":
				if p := params["domain"]; p.Flag != "--target" || !p.Required || !reflect.DeepEqual(p.Aliases, []string{"target"}) {
					t.Fatalf("existing target contract changed: %+v", p)
				}
				if p := params["action"]; p.Default != "run" || p.Position == nil || *p.Position != 1 {
					t.Fatalf("upstream run subcommand order changed: %+v", p)
				}
			}
		})
	}
}
