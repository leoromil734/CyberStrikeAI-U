package recon

import (
	"context"
	"strings"
	"testing"

	"cyberstrike-ai/internal/evidence"
)

func TestNmapMachineEnvelopeRejectsMixedLogsAndMultipleRoots(t *testing.T) {
	const host = `<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host>`
	const document = `<nmaprun>` + host + `</nmaprun>`
	tests := []struct {
		name, data string
		wantHosts  int64
	}{
		{"leading log", "Starting Nmap\n" + document, 0},
		{"trailing log", document + "\nNmap done", 1},
		{"second root", document + document, 1},
		{"host after root", document + host, 1},
		{"nested root", `<nmaprun><nmaprun>` + host + `</nmaprun></nmaprun>`, 0},
		{"nested host", `<nmaprun><unexpected>` + host + `</unexpected></nmaprun>`, 0},
		{"missing end", `<nmaprun>` + host, 1},
		{"late doctype", document + `<!DOCTYPE nmaprun>`, 1},
		{"repeated doctype", `<!DOCTYPE nmaprun><!DOCTYPE nmaprun>` + document, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(context.Background(), "nmap", "xml", strings.NewReader(tt.data), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if !got.Partial || got.State == evidence.Parsed || got.Reason != "invalid_format" || got.Stats.Hosts != tt.wantHosts {
				t.Fatalf("mixed or malformed XML accepted: %+v", got)
			}
		})
	}
}

func TestNmapMachineEnvelopeAllowsWhitespaceCommentsAndMultipleHosts(t *testing.T) {
	const host = `<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host>`
	data := "<?xml version=\"1.0\"?>\n<!DOCTYPE nmaprun>\n<!--offline fixture--><nmaprun>" + host + host + "<runstats/></nmaprun>\n<!--end-->\n"
	got, err := Parse(context.Background(), "nmap", "xml", strings.NewReader(data), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Partial || got.State != evidence.Parsed || got.Stats.Hosts != 2 {
		t.Fatalf("valid XML rejected: %+v", got)
	}
	for _, record := range got.Records {
		if data[record.Location.Offset:record.Location.Offset+record.Location.Length] != host {
			t.Fatalf("host provenance changed: %+v", record.Location)
		}
	}
}
