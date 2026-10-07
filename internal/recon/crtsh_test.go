package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/evidence"
)

const crtshTestHeader = `{"schema":"csai.crtsh.v1","source":"crt.sh","query_domain":"example.test","status":"success","partial":false,"truncated":false,"coverage_complete":false,"candidate_only":true,"verification":"unverified",`

func crtshTestRow(host string) string {
	row := map[string]interface{}{"host": host, "source": "crt.sh", "candidate_only": true, "verification": "unverified",
		"certificates": []map[string]interface{}{{"id": "123456789", "url": "https://crt.sh/?id=123456789", "name": "DNS: *." + host,
			"entry_timestamp": "2020-01-02T03:04:05", "not_before": "2020-01-01T00:00:00", "not_after": "2021-01-01T00:00:00", "time_status": "expired", "wildcard": true}}}
	data, _ := json.Marshal(row)
	return string(data)
}

func crtshTestDocument(rows ...string) string {
	return crtshTestHeader + `"queries":[{"url":"https://crt.sh/?q=example.test&output=json","response_sha256":"` + strings.Repeat("a", 64) + `"}],"records":[` + strings.Join(rows, ",\n ") + `],"counts":{"unique_hosts":` + fmt.Sprint(len(rows)) + `}}`
}

func parseCRTShTest(t *testing.T, data string, limits Limits) ParsedOutput {
	t.Helper()
	got, err := Parse(context.Background(), "crtsh_search", "json", strings.NewReader(data), limits)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCRTShHostsAreOnlyCandidatesWithExactCertificateProvenance(t *testing.T) {
	original := crtshTestDocument(crtshTestRow("example.test"), crtshTestRow("api.example.test"), crtshTestRow("xn--bcher-kva.example.test"))
	for _, tool := range []string{"crtsh", "crtsh_search", " CRTSH_SEARCH "} {
		got, err := Parse(context.Background(), tool, "json", strings.NewReader(original), Limits{})
		if err != nil || got.State != evidence.Parsed || got.Partial || got.Reason != "" || len(got.Records) != 3 {
			t.Fatalf("unexpected parse: %+v %v", got, err)
		}
		if got.Stats.Hosts != 3 || got.Stats.Services != 0 || got.Stats.Endpoints != 0 || got.Stats.Candidates != 0 {
			t.Fatalf("CT names became observed services/findings: %+v", got)
		}
		for _, record := range got.Records {
			if record.Kind != Host || !record.CandidateOnly || record.ScopeState != UnknownScope || record.IP != "" || record.Port != 0 {
				t.Fatalf("candidate promoted: %+v", record)
			}
			loc := record.Location
			if loc.Offset < 0 || loc.Length <= 0 || loc.Offset+loc.Length > int64(len(original)) {
				t.Fatalf("invalid location: %+v", loc)
			}
			region := original[loc.Offset : loc.Offset+loc.Length]
			var row map[string]json.RawMessage
			if err := json.Unmarshal([]byte(region), &row); err != nil || string(row["host"]) != `"`+record.Host+`"` {
				t.Fatalf("row cannot be read from original: %q %v", region, err)
			}
			for _, value := range []string{"123456789", "2020-01-02T03:04:05", "2021-01-01T00:00:00", "expired", "wildcard", "DNS:"} {
				if !strings.Contains(region, value) {
					t.Fatalf("certificate metadata lost: %s", region)
				}
			}
		}
	}
}

func TestCRTShStrictDomainBoundaryAndDeduplication(t *testing.T) {
	original := crtshTestDocument(crtshTestRow("www.example.test"), crtshTestRow("www.example.test"), crtshTestRow("notexample.test"), crtshTestRow("example.test.evil.test"), crtshTestRow("evil.test"))
	got := parseCRTShTest(t, original, Limits{})
	if len(got.Records) != 1 || got.Records[0].Host != "www.example.test" || got.Stats.Rejected != 3 || got.Stats.Hosts != 1 || !got.Partial {
		t.Fatalf("suffix or duplicate filtering failed: %+v", got)
	}
}

func TestCRTShEmptySuccessRemainsCoverageUnknown(t *testing.T) {
	got := parseCRTShTest(t, crtshTestDocument(), Limits{})
	if got.State != evidence.Parsed || got.Partial || got.Reason != "" || len(got.Records) != 0 {
		t.Fatalf("zero became full coverage: %+v", got)
	}
}

func TestCRTShPartialTruncatedAndQueryErrorsCannotBecomeComplete(t *testing.T) {
	for _, tc := range []struct {
		status, state, reason string
		truncated             bool
	}{
		{"partial", evidence.Partial, "crtsh_upstream_partial", false},
		{"partial", evidence.Partial, "crtsh_upstream_truncated", true},
		{"error", evidence.Invalid, "crtsh_query_error", false},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			raw := strings.Replace(crtshTestDocument(), `"status":"success","partial":false`, `"status":"`+tc.status+`","partial":true`, 1)
			if tc.truncated {
				raw = strings.Replace(raw, `"truncated":false`, `"truncated":true`, 1)
			}
			got := parseCRTShTest(t, raw, Limits{})
			if got.State != tc.state || !got.Partial || got.Reason != tc.reason {
				t.Fatalf("lost completion: %+v", got)
			}
		})
	}
}

func TestCRTShInvalidEnvelopeNeverPublishesEarlierRows(t *testing.T) {
	valid := crtshTestDocument(crtshTestRow("example.test"))
	inputs := []string{
		`<html>429 rate limit</html>`, `[]`, `{"error":"busy"}`, `{"records":[]}`, `null`,
		strings.Replace(valid, `"schema":"csai.crtsh.v1"`, `"schema":"crt.sh"`, 1),
		strings.Replace(valid, `"source":"crt.sh"`, `"source":"other"`, 1),
		strings.Replace(valid, `"coverage_complete":false`, `"coverage_complete":true`, 1),
		strings.Replace(valid, `"coverage_complete":false,`, ``, 1),
		strings.Replace(valid, `"coverage_complete":false`, `"coverage_complete":null`, 1),
		strings.Replace(valid, `"candidate_only":true`, `"candidate_only":false`, 1),
		strings.Replace(valid, `"verification":"unverified"`, `"verification":"confirmed"`, 1),
		strings.Replace(valid, `"partial":false`, `"partial":true`, 1),
		strings.Replace(valid, `"partial":false`, `"partial":"false"`, 1),
		strings.Replace(valid, `"truncated":false`, `"truncated":true`, 1),
		strings.Replace(valid, `"status":"success"`, `"status":"unknown"`, 1),
		strings.Replace(valid, `"status":"success","partial":false`, `"status":"error","partial":true`, 1),
		valid + ` false`, valid[:len(valid)-1], valid[:len(valid)-1] + `,"coverage_complete":true}`,
		`{"records":[` + crtshTestRow("example.test") + `],` + crtshTestHeader[1:] + `"counts":{}}`,
	}
	for _, domain := range []string{"", "*.example.test", "https://example.test", "192.0.2.1", "a..example.test", "EXAMPLE.TEST", "example.test.", "example.test?x=y", "foo.123"} {
		inputs = append(inputs, strings.Replace(valid, `"query_domain":"example.test"`, `"query_domain":"`+domain+`"`, 1))
	}
	for _, raw := range inputs {
		got := parseCRTShTest(t, raw, Limits{})
		if got.State != evidence.Invalid || !got.Partial || len(got.Records) != 0 {
			t.Errorf("invalid envelope accepted: %s => %+v", raw, got)
		}
	}
}

func TestCRTShBadRecordEvidenceRejected(t *testing.T) {
	valid := crtshTestRow("example.test")
	bad := []string{
		`{}`, `null`,
		strings.Replace(valid, `"host":"example.test"`, `"host":"https://example.test"`, 1),
		strings.Replace(valid, `"host":"example.test"`, `"host":"*.example.test"`, 1),
		strings.Replace(valid, `"host":"example.test"`, `"host":"_svc.example.test"`, 1),
		strings.Replace(valid, `"host":"example.test"`, `"host":"192.0.2.1"`, 1),
		strings.Replace(valid, `"id":"123456789"`, `"id":"bad"`, 1),
		strings.Replace(valid, `"id":"123456789"`, `"id":123456789`, 1),
		strings.Replace(valid, `https://crt.sh/?id=123456789`, `https://outside.test/`, 1),
		strings.Replace(valid, `"candidate_only":true`, `"candidate_only":false`, 1),
		strings.Replace(valid, `"verification":"unverified"`, `"verification":"confirmed"`, 1),
		strings.Replace(valid, `"entry_timestamp":"2020-01-02T03:04:05"`, `"entry_timestamp":"`+strings.Repeat("a", 65)+`"`, 1),
		strings.Replace(valid, `"name":"DNS: *.example.test"`, `"name":""`, 1),
	}
	for _, row := range bad {
		got := parseCRTShTest(t, crtshTestDocument(row), Limits{})
		if got.State != evidence.Invalid || got.Stats.Rejected != 1 || len(got.Records) != 0 {
			t.Errorf("bad row accepted: %s => %+v", row, got)
		}
	}
}

func TestCRTShResourceLimitsCancellationAndDeclaredJSONOnly(t *testing.T) {
	raw := crtshTestDocument(crtshTestRow("example.test"), crtshTestRow("www.example.test"))
	got := parseCRTShTest(t, raw, Limits{MaxRecords: 1})
	if len(got.Records) != 1 || got.Reason != "record_limit" || !got.Partial {
		t.Fatalf("record limit ignored: %+v", got)
	}
	got = parseCRTShTest(t, raw, Limits{MaxBytes: int64(len(raw) / 2)})
	if !got.Partial || got.Reason != "byte_limit" {
		t.Fatalf("byte limit ignored: %+v", got)
	}
	got = parseCRTShTest(t, raw, Limits{MaxLineBytes: 256})
	if !got.Partial || len(got.Records) != 0 {
		t.Fatalf("row size ignored: %+v", got)
	}
	for _, format := range []string{"text", "jsonl", "log", "csv"} {
		got, err := Parse(context.Background(), "crtsh_search", format, strings.NewReader(raw), Limits{})
		if err != nil || got.State != evidence.Unsupported || len(got.Records) != 0 {
			t.Fatalf("undeclared format guessed: %+v %v", got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, "crtsh_search", "json", strings.NewReader(raw), Limits{}); err != context.Canceled {
		t.Fatalf("cancel lost: %v", err)
	}
}

// The real artifact registry and processor run against an in-memory store;
// tests neither open a database nor invoke Python or network services.
type crtshMemoryStore struct {
	Store
	execution evidence.Execution
	artifacts map[string]evidence.Artifact
	source    Source
	records   []Record
}

func (s *crtshMemoryStore) RecordExecution(ctx context.Context, e evidence.Execution) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	s.execution = e
	return nil
}

func (s *crtshMemoryStore) ResultExecution(ctx context.Context, id string) (evidence.Execution, error) {
	if id != s.execution.ID {
		return evidence.Execution{}, evidence.ErrDenied
	}
	return s.execution, s.execution.Access.Authorize(ctx)
}

func (s *crtshMemoryStore) RegisterArtifact(ctx context.Context, v evidence.VerifiedArtifact) (evidence.Artifact, error) {
	a, err := v.Metadata()
	if err != nil {
		return a, err
	}
	if _, err := s.ResultExecution(ctx, a.ExecutionID); err != nil {
		return a, err
	}
	s.artifacts[a.ID] = a
	return a, nil
}

func (s *crtshMemoryStore) ResultArtifact(ctx context.Context, id string) (evidence.Artifact, error) {
	a, ok := s.artifacts[id]
	if !ok {
		return a, evidence.ErrDenied
	}
	return a, a.Access.Authorize(ctx)
}

func (s *crtshMemoryStore) ImportReconSource(ctx context.Context, source Source, records []Record) (ImportResult, error) {
	if err := source.Access.Authorize(ctx); err != nil {
		return ImportResult{}, err
	}
	var counts Counts
	for _, r := range records {
		if err := r.Validate(); err != nil {
			return ImportResult{}, err
		}
		counts.Add(r.Kind)
	}
	s.source, s.records = source, records
	return ImportResult{Source: source, Records: records, Inserted: counts}, nil
}

func (s *crtshMemoryStore) ReconInventoryCounts(ctx context.Context, id string) (Counts, error) {
	if _, err := s.ResultExecution(ctx, id); err != nil {
		return Counts{}, err
	}
	var counts Counts
	for _, r := range s.records {
		counts.Add(r.Kind)
	}
	return counts, nil
}

func TestCRTShRegisteredOriginalRemainsCandidateEvenInsideAuthorizedScope(t *testing.T) {
	for _, scope := range []string{UnknownScope, InScope, OutOfScope} {
		t.Run(scope, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "output.json")
			original := crtshTestDocument(crtshTestRow("example.test"))
			if err := os.WriteFile(file, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			e := evidence.Execution{ID: "exec-crtsh", Tool: "crtsh_search", Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "o"},
				ScopeID: "scope", AssessmentID: "assessment", Status: "completed", Completion: evidence.Complete, FinishedAt: time.Now()}
			ctx := evidence.WithAccess(context.Background(), e.Access)
			store := &crtshMemoryStore{artifacts: map[string]evidence.Artifact{}}
			registry, err := evidence.NewRegistry(store, []evidence.ManagedRoot{{Path: root, Access: e.Access, ExecutionID: e.ID}}, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = registry.Close() })
			processor := Processor{Store: store, Artifacts: registry, Scope: func(context.Context, evidence.Execution, Record) string { return scope }}
			report, err := processor.Observe(ctx, Event{Execution: e, CappedResult: "preview is not the original",
				Artifacts: []evidence.Candidate{{Path: file, Kind: "output", Format: "json", Completion: evidence.Complete}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Sources) != 1 || report.Sources[0].State != evidence.Parsed || report.Sources[0].Completion != evidence.Complete || report.Sources[0].Reason != "" {
				t.Fatalf("complete CT query output became a permanent gap: %+v", report)
			}
			if report.Inventory.Hosts != 1 || len(report.Records) != 1 || len(report.Artifacts) != 1 {
				t.Fatalf("original not ingested: %+v", report)
			}
			r := report.Records[0]
			if !r.CandidateOnly || r.ScopeState != scope || r.ExecutionID != e.ID || r.ArtifactID == "" || r.Kind != Host || r.IP != "" || r.Port != 0 {
				t.Fatalf("CT promoted or binding lost: %+v", r)
			}
			region, err := registry.ReadRegion(ctx, e.ID, evidence.Region{ArtifactID: r.ArtifactID, Offset: r.Location.Offset, Length: int(r.Location.Length)})
			if err != nil || !strings.Contains(region.Text, "123456789") || !strings.Contains(region.Text, "2021-01-01T00:00:00") {
				t.Fatalf("certificate evidence unreadable: %+v %v", region, err)
			}
			if len(report.Artifacts[0].SHA256) != 64 || report.Sources[0].SHA256 != report.Artifacts[0].SHA256 {
				t.Fatal("original hash not bound to source")
			}
		})
	}
}
