package security

import (
	"path/filepath"
	"reflect"
	"testing"

	"cyberstrike-ai/internal/config"

	"go.uber.org/zap"
)

// Offline only: exercise the real argument builder, never start a scanner.
func TestReconMachineOutputCommandContracts(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args map[string]interface{}
		want []string
	}{
		{"nmap XML stdout", "nmap", map[string]interface{}{"target": "example.invalid"}, []string{"-sT", "-sV", "-sC", "-oX", "-", "example.invalid"}},
		{"nmap scan_type preserves XML", "nmap", map[string]interface{}{"target": "example.invalid", "scan_type": "-sT", "additional_args": "--min-rate 100"}, []string{"-sT", "-oX", "-", "example.invalid", "--min-rate", "100"}},
		{"nmap explicit XML file", "nmap", map[string]interface{}{"target": "example.invalid", "xml_output": "reports/my scan.xml"}, []string{"-sT", "-sV", "-sC", "-oX", "reports/my scan.xml", "example.invalid"}},
		{"nmap explicit text", "nmap", map[string]interface{}{"target": "example.invalid", "xml_output": "", "additional_args": "-oN -"}, []string{"-sT", "-sV", "-sC", "example.invalid", "-oN", "-"}},
		{"nmap custom export unchanged", "nmap", map[string]interface{}{"target": "example.invalid", "xml_output": "", "additional_args": "-oA 'reports/my scan'"}, []string{"-sT", "-sV", "-sC", "example.invalid", "-oA", "reports/my scan"}},
		{"nmap human file separate", "nmap", map[string]interface{}{"target": "example.invalid", "additional_args": "-oN human.txt"}, []string{"-sT", "-sV", "-sC", "-oX", "-", "example.invalid", "-oN", "human.txt"}},
		{"nuclei JSONL stdout", "nuclei", map[string]interface{}{"target": "https://example.invalid"}, []string{"-u", "https://example.invalid", "-jsonl", "-silent"}},
		{"nuclei explicit text", "nuclei", map[string]interface{}{"target": "https://example.invalid", "json_output": false}, []string{"-u", "https://example.invalid", "-silent"}},
		{"nuclei progress opt in", "nuclei", map[string]interface{}{"target": "https://example.invalid", "silent": false}, []string{"-u", "https://example.invalid", "-jsonl"}},
		{"nuclei custom file export unchanged", "nuclei", map[string]interface{}{"target": "https://example.invalid", "json_output": false, "silent": false, "additional_args": "-json-export 'reports/my scan.json'"}, []string{"-u", "https://example.invalid", "-json-export", "reports/my scan.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", tt.tool+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			executor := &Executor{logger: zap.NewNop()}
			got := executor.buildCommandArgs(tt.tool, tool, tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("arguments = %#v, want %#v", got, tt.want)
			}
		})
	}
}
