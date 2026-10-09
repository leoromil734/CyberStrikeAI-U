package recon

import "testing"

func TestNativeStdoutContractOnlyActualCLIFlags(t *testing.T) {
	for _, tc := range []struct {
		tool string
		argv []string
		want string
	}{
		{"nmap", []string{"example.invalid"}, "text"},
		{"nmap", []string{"-sT", "-oX", "-", "example.invalid"}, "xml"},
		{"nmap", []string{"-oX-"}, "xml"},
		{"nmap", []string{"-oX", "user chosen.xml"}, "text"},
		{"nmap", []string{"-oX", ""}, "text"},
		{"nmap", []string{"-oX", "-", "-oN", "-"}, "text"},
		{"nmap", []string{"-oX", "-", "-oG-"}, "text"},
		{"nmap", []string{"-oX", "-", "-oN", "text.log"}, "xml"},
		{"nmap", []string{"-oX", "-", "-oA", "file"}, "text"},
		{"nmap", []string{"-oX", "-", "-oX", "-"}, "text"},
		{"nuclei", []string{"-silent"}, "text"},
		{"nuclei", []string{"-jsonl", "-silent"}, "jsonl"},
		{"nuclei", []string{"-jsonl", "-jsonl=false"}, "text"},
		{"nuclei", []string{"-jsonl=false", "-j=true"}, "jsonl"},
		{"nuclei", []string{"--json=true"}, "jsonl"},
		{"nuclei", []string{"-json-export", "data.json"}, "text"},
		{"nuclei", []string{"-jsonl-export", "data.jsonl"}, "text"},
		{"nuclei", []string{"-u", "jsonl"}, "text"},
		{"oneforall", []string{"--fmt", "json", "run"}, "log"},
	} {
		if got := NativeStdoutFormat(tc.tool, tc.argv); got != tc.want {
			t.Fatalf("%s %v: %s want %s", tc.tool, tc.argv, got, tc.want)
		}
	}
}
