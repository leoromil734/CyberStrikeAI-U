package recon

import (
	"context"
	"strings"
	"testing"

	"cyberstrike-ai/internal/evidence"
)

func TestReconCoreOfflineFormats(t *testing.T) {
	tests := []struct {
		name, tool, format, data                   string
		hosts, services, endpoints, js, candidates int64
	}{
		{"fofa json", "fofa", "json", `{"fields":["host","ip","port","protocol"],"results":[["https://example.test:8443/users/42?q=a%2Fb","192.0.2.1","8443","https"]],"error":false}`, 2, 1, 1, 0, 0},
		{"fofa csv", "fofa", "csv", "host,ip,port,protocol\nexample.test,192.0.2.1,443,tcp\n", 2, 1, 0, 0, 0},
		{"subfinder text", "subfinder", "text", "a.example.test\r\nb.example.test\r\n", 2, 0, 0, 0, 0},
		{"subfinder jsonl", "subfinder", "jsonl", "{\"host\":\"a.example.test\",\"source\":\"crtsh\"}\n", 1, 0, 0, 0, 0},
		{"oneforall csv", "oneforall", "csv", "id,subdomain,ip\n1,a.example.test,192.0.2.1\n", 1, 0, 0, 0, 0},
		{"dnsx text", "dnsx", "text", "a.example.test [192.0.2.1]\n", 2, 0, 0, 0, 0},
		{"dnsx jsonl", "dnsx", "jsonl", "{\"host\":\"a.example.test\",\"a\":[\"192.0.2.1\"],\"aaaa\":[\"2001:db8::1\"]}\n", 3, 0, 0, 0, 0},
		{"httpx jsonl", "httpx", "jsonl", "{\"url\":\"https://example.test:8443/api/42?role=user\",\"status_code\":200}\n", 1, 1, 1, 0, 0},
		{"httpx text", "httpx", "text", "https://example.test:8443/api/42?role=user [200] [Title]\n", 1, 1, 1, 0, 0},
		{"naabu text", "naabu", "text", "example.test:8443\n[2001:db8::1]:443\n", 2, 2, 0, 0, 0},
		{"naabu jsonl", "naabu", "jsonl", "{\"host\":\"example.test\",\"ip\":\"192.0.2.1\",\"port\":8443}\n", 1, 1, 0, 0, 0},
		{"nmap xml", "nmap", "xml", `<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="example.test"/></hostnames><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="https"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>`, 2, 2, 0, 0, 0},
		{"gau text", "gau", "text", "https://example.test/users/42?q=one&q=two\n", 1, 1, 1, 0, 0},
		{"katana jsonl", "katana", "jsonl", "{\"request\":{\"method\":\"GET\",\"endpoint\":\"https://example.test/assets/main.js?v=7\"}}\n", 1, 1, 1, 1, 0},
		{"jsapiscan csv", "jsapiscan", "csv", "URL,Method,Status,Length\nhttps://example.test/api/users/42?lang=zh,POST,200,12\n", 1, 1, 1, 0, 0},
		{"nuclei candidates", "nuclei", "jsonl", "{\"template-id\":\"example-template\",\"matched-at\":\"https://example.test/users/42?role=admin\",\"info\":{\"severity\":\"high\"},\"extracted-results\":[\"secret-must-not-be-retained\"]}\n", 0, 0, 0, 0, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(context.Background(), test.tool, test.format, strings.NewReader(test.data), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if got.State != evidence.Parsed || got.Partial || got.Stats.Hosts != test.hosts || got.Stats.Services != test.services || got.Stats.Endpoints != test.endpoints || got.Stats.JS != test.js || got.Stats.Candidates != test.candidates {
				t.Fatalf("unexpected parse: %+v", got)
			}
			for _, r := range got.Records {
				if !r.CandidateOnly || r.ScopeState != UnknownScope {
					t.Fatalf("parser authorized a target: %+v", r)
				}
				if r.Location.Offset < 0 || r.Location.Length <= 0 || r.Location.Offset+r.Location.Length > int64(len(test.data)) {
					t.Fatalf("invalid provenance location: %+v", r.Location)
				}
			}
		})
	}
}

func TestReconRoutesPortsAndExactLocationsPreserved(t *testing.T) {
	original := "https://example.test:08443/users/42%2Fpart?item=7&item=8&next=%2Fadmin#section\r\nhttps://example.test:08443/users/43%2Fpart?item=7&item=8&next=%2Fadmin#section\r\n"
	got, err := Parse(context.Background(), "gau", "text", strings.NewReader(original), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var endpoints []Record
	for _, r := range got.Records {
		if r.Kind == Endpoint {
			endpoints = append(endpoints, r)
		}
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints: %+v", got)
	}
	first := endpoints[0]
	if first.RawPort != "08443" || first.Port != 8443 || first.RawPath != "/users/42%2Fpart?item=7&item=8&next=%2Fadmin" || !strings.HasSuffix(first.RawURL, "#section") {
		t.Fatalf("route lost: %+v", first)
	}
	if first.Identity() == endpoints[1].Identity() {
		t.Fatal("route parameter identities collapsed")
	}
	for _, r := range endpoints {
		rangeText := original[r.Location.Offset : r.Location.Offset+r.Location.Length]
		if rangeText != r.RawURL+"\r\n" {
			t.Fatalf("wrong actual location: %q", rangeText)
		}
	}
}

func TestReconUnsupportedAndPreviewManifestNeverBecomeInventory(t *testing.T) {
	tests := []struct{ tool, format, data string }{
		{"jsapiscan", "json", `{"timed_out":false,"candidate_count":90000,"candidates_preview":[{"url":"https://example.test/preview"}]}`},
		{"nuclei", "text", "[critical-template] [http] [critical] https://example.test\n"},
		{"fofa", "json", `{"results":[["example.test","443"]],"fields":["host","port"]}`},
		{"fofa", "csv", "title,ip\nsomewhere,192.0.2.1\n"},
		{"nmap", "xml", `<!DOCTYPE nmaprun SYSTEM "https://outside.test/schema"><nmaprun/>`},
		{"unknown-tool", "jsonl", `{"url":"https://example.test"}`},
	}
	for _, test := range tests {
		got, err := Parse(context.Background(), test.tool, test.format, strings.NewReader(test.data), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if got.State != evidence.Unsupported || len(got.Records) > 0 {
			t.Fatalf("unsupported envelope ingested: %+v", got)
		}
	}
}

func TestReconPartialBadFormatAndLargeFiles(t *testing.T) {
	got, err := Parse(context.Background(), "httpx", "jsonl", strings.NewReader("{\"url\":\"https://example.test/a\"}\n{broken json\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != evidence.Partial || !got.Partial || got.Stats.Rejected != 1 || got.Stats.Endpoints != 1 {
		t.Fatalf("partial parse: %+v", got)
	}
	got, err = Parse(context.Background(), "httpx", "jsonl", strings.NewReader("{broken json\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != evidence.Invalid || got.Stats.Records != 0 {
		t.Fatalf("invalid format: %+v", got)
	}
	got, err = Parse(context.Background(), "subfinder", "text", strings.NewReader(strings.Repeat("large.example.test\n", 300000)), Limits{MaxRecords: 20})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != evidence.Partial || got.Reason != "record_limit" || len(got.Records) != 20 {
		t.Fatalf("record limit: %+v", got)
	}
	got, err = Parse(context.Background(), "subfinder", "text", strings.NewReader(strings.Repeat("x", 2<<20)), Limits{MaxLineBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Partial || len(got.Records) != 0 {
		t.Fatalf("large line: %+v", got)
	}
	got, err = Parse(context.Background(), "subfinder", "text", strings.NewReader(strings.Repeat("a.example.test\n", 20)), Limits{MaxBytes: 40})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Partial || got.Reason != "byte_limit" {
		t.Fatalf("byte cap: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Parse(ctx, "gau", "text", strings.NewReader("https://example.test"), Limits{}); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestReconNucleiNeverProducesFormalFinding(t *testing.T) {
	got, err := Parse(context.Background(), "nuclei", "jsonl", strings.NewReader(`{"template-id":"candidate","matched-at":"example.test:8443","info":{"severity":"critical"}}`), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 || got.Records[0].Kind != Candidate || !got.Records[0].CandidateOnly || got.Records[0].TemplateID != "candidate" {
		t.Fatalf("candidate promotion: %+v", got)
	}
}
