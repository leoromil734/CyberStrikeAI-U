package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/evidence"
)

func TestOneForAllJSONEnvelopesAndExactLocations(t *testing.T) {
	row := `{"subdomain":"API.Example.test","domain":"example.test","url":"https://do-not-infer.test/path","ip":"192.0.2.1"}`
	for _, original := range []string{row, " \n[\n " + row + ",\n" + row + "\n]\n", `{"metadata":{"url":"https://ignored.test"},"data":[` + row + `]}`, `{"results":[` + row + `],"total":1}`} {
		got, err := Parse(context.Background(), "oneforall", "json", strings.NewReader(original), Limits{})
		if err != nil || got.State != evidence.Parsed || got.Partial || len(got.Records) == 0 {
			t.Fatalf("parse %s: %+v %v", original, got, err)
		}
		for _, record := range got.Records {
			if record.Kind != Host || record.Host != "api.example.test" || record.RawHost != "API.Example.test" || record.RawURL != "" || record.IP != "" || !record.CandidateOnly || record.ScopeState != UnknownScope {
				t.Fatalf("guessed/promoted record: %+v", record)
			}
			loc := record.Location
			region := original[loc.Offset : loc.Offset+loc.Length]
			if !json.Valid([]byte(region)) || region != row {
				t.Fatalf("not exact original row: %q (%+v)", region, loc)
			}
		}
	}
}

func TestOneForAllJSONInvalidOrLogsNeverInventHosts(t *testing.T) {
	for _, original := range []string{
		`[{"subdomain":"api.example.test"}] log https://guess.test`,
		`[{"subdomain":"api.example.test"},`,
		`[INFO] https://guess.test`,
		`{"message":"Finished https://guess.test"}`,
		`{"preview":[{"subdomain":"guess.test"}]}`,
		`{"results":[{"subdomain":"api.example.test"}],"results":[]}`,
		`null`, `"https://guess.test"`,
	} {
		got, err := Parse(context.Background(), "oneforall", "json", strings.NewReader(original), Limits{})
		if err != nil || got.State != evidence.Invalid || len(got.Records) != 0 {
			t.Fatalf("invalid original accepted: %q %+v %v", original, got, err)
		}
	}
	got, err := Parse(context.Background(), "oneforall", "json", strings.NewReader(`[]`), Limits{})
	if err != nil || got.State != evidence.Parsed || got.Stats.Records != 0 {
		t.Fatalf("empty export: %+v %v", got, err)
	}
}

func TestOneForAllJSONLimitsAndRejectedRows(t *testing.T) {
	for _, test := range []struct {
		body   string
		limits Limits
		reason string
		count  int
	}{
		{`[{"subdomain":"a.example.test"},{"subdomain":"b.example.test"}]`, Limits{MaxRecords: 1}, "record_limit", 1},
		{`[{"subdomain":"a.example.test","long":"` + strings.Repeat("x", 500) + `"}]`, Limits{MaxLineBytes: 128}, "record_byte_limit", 0},
		{`[{"subdomain":"a.example.test"},{"subdomain":"b.example.test"}]`, Limits{MaxBytes: 35}, "byte_limit", 0},
		{`[{"subdomain":"a.example.test"},{"url":"https://not-a-host.test"},null]`, Limits{}, "rejected_records", 1},
	} {
		got, err := Parse(context.Background(), "oneforall", "json", strings.NewReader(test.body), test.limits)
		if err != nil || !got.Partial || got.Reason != test.reason || len(got.Records) != test.count {
			t.Fatalf("limits: %+v %v (wanted %s/%d)", got, err, test.reason, test.count)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, "oneforall", "json", strings.NewReader(`[]`), Limits{}); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestOneForAllAndHTTPXPDRegisteredSourceHashes(t *testing.T) {
	for _, tc := range []struct{ tool, format, body, canonical string }{
		{"oneforall", "json", `[{"subdomain":"api.example.test"}]`, "oneforall"},
		{"httpx-pd", "jsonl", `{"url":"https://example.test/path?a=1"}` + "\n", "httpx"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "original")
			if err := os.WriteFile(file, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			e := evidence.Execution{ID: "fixture-execution", Tool: tc.tool, Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "o"}, Status: "completed", Completion: evidence.Complete, FinishedAt: time.Now()}
			ctx := evidence.WithAccess(context.Background(), e.Access)
			store := &crtshMemoryStore{artifacts: map[string]evidence.Artifact{}}
			registry, err := evidence.NewRegistry(store, []evidence.ManagedRoot{{Path: root, Access: e.Access, ExecutionID: e.ID}}, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			processor := Processor{Store: store, Artifacts: registry}
			report, err := processor.Observe(ctx, Event{Execution: e, Artifacts: []evidence.Candidate{{Path: file, Kind: "output", Format: tc.format, Completion: evidence.Complete}}})
			if err != nil || len(report.Sources) != 1 || len(report.Records) == 0 || report.Sources[0].Tool != tc.canonical {
				t.Fatalf("original/alias registration failed: %+v %v", report, err)
			}
			sum := sha256.Sum256([]byte(tc.body))
			if report.Sources[0].SHA256 != hex.EncodeToString(sum[:]) || report.Artifacts[0].SHA256 != report.Sources[0].SHA256 {
				t.Fatal("hash provenance was lost")
			}
			for _, r := range report.Records {
				if r.ExecutionID != e.ID || r.ArtifactID == "" || !r.CandidateOnly || r.ScopeState != UnknownScope {
					t.Fatalf("source binding or candidate restriction lost: %+v", r)
				}
				region, err := registry.ReadRegion(ctx, e.ID, evidence.Region{ArtifactID: r.ArtifactID, Offset: r.Location.Offset, Length: int(r.Location.Length)})
				if err != nil || !json.Valid([]byte(strings.TrimSpace(region.Text))) {
					t.Fatalf("exact row cannot be read: %+v %v", region, err)
				}
			}
		})
	}
}

func TestHTTPXPDCanonicalAlias(t *testing.T) {
	if CanonicalTool(" HTTPX-PD ") != "httpx" {
		t.Fatal("binary alias is not canonical")
	}
	got, err := Parse(context.Background(), "httpx-pd", "jsonl", strings.NewReader(`{"url":"https://example.test/path?a=1"}`), Limits{})
	if err != nil || got.State != evidence.Parsed || got.Stats.Endpoints != 1 {
		t.Fatalf("alias did not use httpx parser: %+v %v", got, err)
	}
	if CanonicalTool("sh") != "sh" || CanonicalTool("python3") != "python3" {
		t.Fatal("shell wrappers became scanners")
	}
}
