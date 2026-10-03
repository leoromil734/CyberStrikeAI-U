package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
	"go.uber.org/zap"
)

func newResultArtifactTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(OpenOptions{Dialect: DialectSQLite, Path: filepath.Join(t.TempDir(), "results.db"), SkipInit: true, Logger: zap.NewNop()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = db.initResultArtifactsTables(); err != nil {
		t.Fatal(err)
	}
	return db
}
func resultTestExecution(id string) evidence.Execution {
	return evidence.Execution{ID: id, Access: evidence.Access{ProjectID: "p1", ConversationID: "c1", Owner: "u1"}, ScopeID: "scope1", AssessmentID: "assessment1", Tool: "gau", Status: "completed", Completion: evidence.Complete, StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now()}
}
func resultTestFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func resultProcessor(t *testing.T, db *DB, e evidence.Execution, data, format string) (*recon.Processor, context.Context, evidence.Candidate) {
	t.Helper()
	root := t.TempDir()
	file := filepath.Join(root, "output")
	resultTestFile(t, file, data)
	registry, err := evidence.NewRegistry(db, []evidence.ManagedRoot{{Path: root, Access: e.Access, ExecutionID: e.ID}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	processor := &recon.Processor{Store: db, Artifacts: registry, Scope: func(context.Context, evidence.Execution, recon.Record) string { return recon.InScope }}
	return processor, evidence.WithAccess(context.Background(), e.Access), evidence.Candidate{Path: file, Kind: "output", Format: format, Completion: evidence.Complete}
}

func TestResultArtifactsMetadataFirstAndPreviewIgnored(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("missing")
	p, ctx, _ := resultProcessor(t, db, e, "unused", "text")
	report, err := p.Observe(ctx, recon.Event{Execution: e, CappedResult: strings.Repeat("https://example.test/preview\n", 100000)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Inventory.Total() != 0 || len(report.Sources) != 1 || report.Sources[0].State != recon.MissingOriginal || report.Sources[0].Completion != evidence.Partial {
		t.Fatalf("preview ingested: %+v", report)
	}
	if _, err = db.ResultExecution(ctx, e.ID); err != nil {
		t.Fatalf("execution metadata missing: %v", err)
	}
	var rawMetadata string
	if err = db.QueryRow(`SELECT tool FROM result_execution_metadata WHERE execution_id=?`, e.ID).Scan(&rawMetadata); err != nil {
		t.Fatal(err)
	}
	if len(rawMetadata) > 128 {
		t.Fatal("output stored as metadata")
	}
}

func TestResultArtifactsIdempotentImportRealDeltaAndRouteRetention(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("first")
	data := "https://example.test:8443/users/42?item=7&item=8\nhttps://example.test:8443/users/42?item=7&item=8\nhttps://example.test:8443/users/43?item=7&item=8\n"
	p, ctx, candidate := resultProcessor(t, db, e, data, "text")
	report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{candidate}, ExpiresAt: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Inserted.Hosts != 1 || report.Inserted.Services != 1 || report.Inserted.Endpoints != 2 || report.Sources[0].Stats.Endpoints != 3 {
		t.Fatalf("actual insert delta: %+v", report)
	}
	artifact, err := db.ResultArtifact(ctx, report.Artifacts[0].ID)
	if err != nil || artifact.ParseState != evidence.Parsed || artifact.Stats.Records != 9 {
		t.Fatalf("artifact parse metadata: %+v %v", artifact, err)
	}
	records, err := db.ReconInventory(ctx, e.ID, recon.Endpoint, 100, 0)
	if err != nil || len(records) != 2 {
		t.Fatalf("inventory: %+v %v", records, err)
	}
	for _, r := range records {
		if r.CandidateOnly || r.Port != 8443 || r.RawPort != "8443" || !strings.Contains(r.RawPath, "item=7&item=8") || !(strings.Contains(r.RawURL, "/users/42?") || strings.Contains(r.RawURL, "/users/43?")) {
			t.Fatalf("route metadata changed: %+v", r)
		}
	}
	again, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{candidate}})
	if err != nil {
		t.Fatal(err)
	}
	if again.Inserted.Total() != 0 || again.Sources[0].Inserted.Total() != 4 || len(again.Records) != 0 {
		t.Fatalf("non-idempotent source: %+v", again)
	}
	sources, err := db.ReconSources(ctx, e.ID, 100, 0, time.Now())
	if err != nil || len(sources) != 1 || !sources[0].Expired {
		t.Fatalf("source freshness: %+v %v", sources, err)
	}
	sourceRecords, err := db.ReconSourceRecords(ctx, sources[0].ID, 100, 0)
	if err != nil || len(sourceRecords) != 4 {
		t.Fatalf("provenance: %+v %v", sourceRecords, err)
	}
	for _, r := range sourceRecords {
		if r.ArtifactID != artifact.ID || r.ExecutionID != e.ID || r.SourceID != sources[0].ID || r.Location.Length == 0 {
			t.Fatalf("broken provenance: %+v", r)
		}
	}
	// A new execution with the same original content adds provenance, not inventory.
	second := resultTestExecution("second")
	p2, ctx2, c2 := resultProcessor(t, db, second, data, "text")
	later, err := p2.Observe(ctx2, recon.Event{Execution: second, Artifacts: []evidence.Candidate{c2}})
	if err != nil {
		t.Fatal(err)
	}
	if later.Inserted.Total() != 0 || later.Sources[0].Inserted.Total() != 0 || later.Inventory.Total() != 4 {
		t.Fatalf("existing inventory counted as new: %+v", later)
	}
	secondRecords, err := db.ReconSourceRecords(ctx2, later.Sources[0].ID, 100, 0)
	if err != nil || len(secondRecords) != 4 {
		t.Fatalf("second source lost: %+v %v", secondRecords, err)
	}
	for _, r := range secondRecords {
		if r.ExecutionID != second.ID || r.ArtifactID != later.Artifacts[0].ID {
			t.Fatalf("wrong source original: %+v", r)
		}
	}
}

func TestResultArtifactsScopeAssessmentAndOwnershipIsolation(t *testing.T) {
	db := newResultArtifactTestDB(t)
	first := resultTestExecution("first")
	p, ctx, c := resultProcessor(t, db, first, "https://example.test/users/42?x=1\n", "text")
	report, err := p.Observe(ctx, recon.Event{Execution: first, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []evidence.Execution{
		func() evidence.Execution { e := resultTestExecution("different-scope"); e.ScopeID = "scope2"; return e }(),
		func() evidence.Execution {
			e := resultTestExecution("different-assessment")
			e.AssessmentID = "assessment2"
			return e
		}(),
		func() evidence.Execution { e := resultTestExecution("different-project"); e.ProjectID = "p2"; return e }(),
		func() evidence.Execution { e := resultTestExecution("different-owner"); e.Owner = "u2"; return e }(),
		func() evidence.Execution {
			e := resultTestExecution("different-conversation")
			e.ConversationID = "c2"
			return e
		}(),
	} {
		p2, ctx2, c2 := resultProcessor(t, db, changed, "https://example.test/users/42?x=1\n", "text")
		next, err := p2.Observe(ctx2, recon.Event{Execution: changed, Artifacts: []evidence.Candidate{c2}})
		if err != nil || next.Inserted.Total() != 3 {
			t.Fatalf("partition reused: %+v %v", next, err)
		}
	}
	foreign := evidence.WithAccess(ctx, evidence.Access{ProjectID: "p2", ConversationID: first.ConversationID, Owner: first.Owner})
	if _, err = db.ResultArtifact(foreign, report.Artifacts[0].ID); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("foreign artifact lookup: %v", err)
	}
	if _, err = db.ReconSourceRecords(foreign, report.Sources[0].ID, 100, 0); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("foreign provenance: %v", err)
	}
	if _, err = db.ReconInventoryCounts(foreign, first.ID); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("foreign count: %v", err)
	}
	moved := first
	moved.ScopeID = "scope2"
	if err = db.RecordExecution(ctx, moved); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("execution scope reassigned: %v", err)
	}
	if _, err = db.ResultExecution(context.Background(), first.ID); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("unbound context allowed: %v", err)
	}
	if _, err = db.RegisterArtifact(ctx, evidence.VerifiedArtifact{}); !errors.Is(err, evidence.ErrUnsafePath) {
		t.Fatalf("manufactured artifact accepted: %v", err)
	}
}

func TestResultArtifactsTimeoutMalformedAndUnsupportedStates(t *testing.T) {
	db := newResultArtifactTestDB(t)
	tests := []struct {
		id, tool, format, data, state string
		timeout                       bool
		completion                    string
		expected                      int64
	}{
		{"timeout", "gau", "text", "https://example.test/users/42?x=1\n", evidence.Partial, true, evidence.Partial, 3},
		{"malformed", "httpx", "jsonl", "{\"url\":\"https://example.test/a\"}\n{invalid json\n", evidence.Partial, false, evidence.Partial, 3},
		{"bad", "httpx", "jsonl", "{invalid json\n", evidence.Invalid, false, evidence.Partial, 0},
		{"unsupported", "jsapiscan", "json", `{"candidate_count":90000,"candidates_preview":[{"url":"https://example.test/a"}]}`, evidence.Unsupported, false, evidence.Complete, 0},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			e := resultTestExecution(test.id)
			e.Tool = test.tool
			e.TimedOut = test.timeout
			e.AssessmentID = test.id
			p, ctx, c := resultProcessor(t, db, e, test.data, test.format)
			report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Sources) != 1 || report.Sources[0].State != test.state || report.Sources[0].Completion != test.completion || report.Inventory.Total() != test.expected {
				t.Fatalf("incorrect source status: %+v", report)
			}
		})
	}
}

func TestResultArtifactsUnknownOutOfScopeAndNucleiStayCandidates(t *testing.T) {
	db := newResultArtifactTestDB(t)
	for _, state := range []string{recon.UnknownScope, recon.OutOfScope} {
		e := resultTestExecution(state)
		e.AssessmentID = state
		p, ctx, c := resultProcessor(t, db, e, "https://outside.test/api/42?param=3\n", "text")
		p.Scope = func(context.Context, evidence.Execution, recon.Record) string { return state }
		report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Records {
			if !r.CandidateOnly || r.ScopeState != state {
				t.Fatalf("candidate authorized: %+v", r)
			}
		}
	}
	e := resultTestExecution("unknown-assessment")
	e.AssessmentID = ""
	p, ctx, c := resultProcessor(t, db, e, "https://example.test/a\n", "text")
	report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Records {
		if !r.CandidateOnly || r.ScopeState != recon.UnknownScope {
			t.Fatalf("unknown assessment authorized: %+v", r)
		}
	}
	e = resultTestExecution("nuclei")
	e.Tool = "nuclei"
	p, ctx, c = resultProcessor(t, db, e, `{"template-id":"candidate-template","matched-at":"https://example.test/users/42?x=1","info":{"severity":"critical"}}`, "jsonl")
	report, err = p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Inserted.Candidates != 1 || len(report.Records) != 1 || !report.Records[0].CandidateOnly {
		t.Fatalf("nuclei finding promoted: %+v", report)
	}
}

func TestResultArtifactsRejectedOriginalStillLeavesMetadata(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("unsafe")
	p, ctx, c := resultProcessor(t, db, e, "safe", "text")
	c.Path = filepath.Join(t.TempDir(), "unregistered")
	resultTestFile(t, c.Path, "https://outside.test/not-owned")
	report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.ArtifactErrors) != 1 || len(report.Artifacts) != 0 || report.Inventory.Total() != 0 || report.Sources[0].Reason != "original_rejected" {
		t.Fatalf("unsafe original accepted: %+v", report)
	}
	if _, err = db.ResultExecution(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
}

func TestResultArtifactsParserVersionAndHashIdempotency(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("versions")
	p, ctx, c := resultProcessor(t, db, e, "https://example.test/users/42?x=1\n", "text")
	report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	s := report.Sources[0]
	s.ParserVersion = "core-offline/v2"
	next, err := db.ImportReconSource(ctx, s, report.Records)
	if err != nil {
		t.Fatal(err)
	}
	if next.Duplicate || next.Inserted.Total() != 0 {
		t.Fatalf("parser version source id: %+v", next)
	}
	again, err := db.ImportReconSource(ctx, s, report.Records)
	if err != nil || !again.Duplicate {
		t.Fatalf("parser-version idempotency: %+v %v", again, err)
	}
	resultTestFile(t, c.Path, "https://example.test/users/43?x=1\n")
	changed, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Sources[0].SHA256 == report.Sources[0].SHA256 || changed.Inserted.Endpoints != 1 || changed.Inserted.Hosts != 0 {
		t.Fatalf("hash source/delta: %+v", changed)
	}
}

func TestResultArtifactsLargeOriginalAndBoundedReport(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("large")
	p, ctx, c := resultProcessor(t, db, e, strings.Repeat("https://example.test/users/42?param=keep-this-value\n", 100000), "text")
	p.Limits = recon.Limits{MaxRecords: 10}
	p.MaxReturnedRecords = 1
	report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Sources[0].State != evidence.Partial || report.Sources[0].Reason != "record_limit" || !report.RecordsTruncated || len(report.Records) != 1 || report.Inventory.Total() != 3 {
		t.Fatalf("large original result: %+v", report)
	}
	if report.Artifacts[0].Size < 1<<20 || report.Artifacts[0].ParseState != evidence.Partial {
		t.Fatalf("missing actual file metadata: %+v", report.Artifacts[0])
	}
	var maxStats int
	if err = db.QueryRow(`SELECT MAX(LENGTH(stats_json)) FROM recon_sources`).Scan(&maxStats); err != nil {
		t.Fatal(err)
	}
	if maxStats > 1024 {
		t.Fatalf("oversized stats: %d", maxStats)
	}
	var maxRoute int
	if err = db.QueryRow(`SELECT MAX(LENGTH(raw_url)) FROM recon_inventory`).Scan(&maxRoute); err != nil {
		t.Fatal(err)
	}
	if maxRoute > 8192 {
		t.Fatalf("oversized inventory route: %d", maxRoute)
	}
}

func TestResultArtifactsCompletenessCanDowngradeButNeverUpgrade(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("downgrade")
	p, ctx, c := resultProcessor(t, db, e, "https://example.test/a\n", "text")
	first, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	e.TimedOut = true
	second, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	if second.Inserted.Total() != 0 || second.Artifacts[0].Completion != evidence.Partial || second.Sources[0].Completion != evidence.Partial || second.Sources[0].State != evidence.Partial {
		t.Fatalf("timeout downgrade lost: %+v", second)
	}
	e.TimedOut = false
	third, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	if third.Sources[0].Completion != evidence.Partial || third.Sources[0].ID != first.Sources[0].ID {
		t.Fatalf("same original upgraded: %+v", third)
	}
}

func TestResultArtifactsGenericExecutorUsesTrustedParserIdentity(t *testing.T) {
	db := newResultArtifactTestDB(t)
	e := resultTestExecution("generic")
	e.Tool = "exec"
	p, ctx, c := resultProcessor(t, db, e, "{\"url\":\"https://example.test/users/42?x=1\"}\n", "jsonl")
	if err := db.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	e.ParserTool = "httpx"
	report, err := p.Observe(ctx, recon.Event{Execution: e, Artifacts: []evidence.Candidate{c}})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := db.ResultExecution(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Inserted.Endpoints != 1 || report.Sources[0].Tool != "httpx" || metadata.Tool != "exec" || metadata.ParserTool != "httpx" {
		t.Fatalf("generic executor identity lost: %+v %+v", metadata, report)
	}
	e.ParserTool = "nuclei"
	if err = db.RecordExecution(ctx, e); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("parser identity reassigned: %v", err)
	}
}

func TestResultArtifactsPostgresSchemaUsesPortableAdapter(t *testing.T) {
	statements := splitSQLStatements(ResultArtifactsSchema)
	if len(statements) < 8 {
		t.Fatalf("schema statement split: %d", len(statements))
	}
	for _, statement := range statements {
		pg := DialectPostgres.Adapt(statement)
		if strings.Contains(pg, "AUTOINCREMENT") || strings.Contains(pg, "PRAGMA") || strings.Contains(pg, "BLOB") {
			t.Fatalf("nonportable DDL: %s", pg)
		}
	}
	pg := DialectPostgres.Adapt(`INSERT INTO result_artifacts(id,size) VALUES (?,?) ON CONFLICT(id) DO NOTHING`)
	if !strings.Contains(pg, "VALUES ($1,$2)") {
		t.Fatalf("placeholder adaptation: %s", pg)
	}
}
