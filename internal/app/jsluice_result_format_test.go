package app

import "testing"

func TestMachineResultFormatUsesInvocationNotLogsOrCurrentDefaults(t *testing.T) {
	for _, tt := range []struct {
		name, tool, want string
		args             map[string]interface{}
	}{
		{"nmap stdout", "nmap", "xml", map[string]interface{}{"xml_output": "-"}},
		{"nmap file", "nmap", "text", map[string]interface{}{"xml_output": "scan.xml"}},
		{"nmap disabled", "nmap", "text", map[string]interface{}{"xml_output": ""}},
		{"historical unknown", "nmap", "text", nil},
		{"explicit nmap flag", "nmap", "xml", map[string]interface{}{"additional_args": "-oX -"}},
		{"direct nmap", "nmap", "xml", map[string]interface{}{"command": "nmap -oX - 192.0.2.1"}},
		{"quoted direct nmap", "nmap", "xml", map[string]interface{}{"command": "nmap -oX '-' 192.0.2.1"}},
		{"mixed stdout", "nmap", "text", map[string]interface{}{"xml_output": "-", "additional_args": "-oN -"}},
		{"duplicate output", "nmap", "text", map[string]interface{}{"xml_output": "-", "additional_args": "-oX file.xml"}},
		{"nuclei jsonl", "nuclei", "jsonl", map[string]interface{}{"json_output": true}},
		{"nuclei explicit text", "nuclei", "text", map[string]interface{}{"json_output": false}},
		{"nuclei export not stdout", "nuclei", "text", map[string]interface{}{"additional_args": "-jsonl-export scan.jsonl"}},
		{"nuclei explicit override", "nuclei", "text", map[string]interface{}{"json_output": true, "additional_args": "-jsonl=false"}},
		{"nuclei direct", "nuclei", "jsonl", map[string]interface{}{"command": "nuclei -jsonl -silent -u https://example.test"}},
		{"exec nmap ignores named option", "nmap", "text", map[string]interface{}{"command": "nmap 192.0.2.1", "xml_output": "-"}},
		{"exec nuclei ignores named option", "nuclei", "text", map[string]interface{}{"command": "nuclei -u https://example.test", "json_output": true}},
		{"exec export only", "nuclei", "text", map[string]interface{}{"command": "nuclei -jsonl-export file.jsonl", "json_output": true}},
		{"oneforall export is not stdout", "oneforall", "log", map[string]interface{}{"fmt": "json"}},
		{"jsluice summary", "jsluice", "log", map[string]interface{}{"mode": "urls"}},
		{"legacy summary", "jsapiscan", "log", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resultFormat(tt.tool, tt.args); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
	if !reconTool("jsluice") || !reconTool("csai-jsluice") {
		t.Fatal("jsluice not recognized as recon")
	}
}
