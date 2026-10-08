package agentfinalizer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
)

// In-memory metadata store, but real local originals and Registry checks. No DB,
// network, shell, or fake public verification token is needed for these tests.
type coverageOriginalStore struct {
	e         evidence.Execution
	artifacts map[string]evidence.Artifact
}

func (s *coverageOriginalStore) RecordExecution(ctx context.Context, e evidence.Execution) error {
	s.e = e
	return e.Validate(ctx)
}
func (s *coverageOriginalStore) ResultExecution(ctx context.Context, id string) (evidence.Execution, error) {
	if id != s.e.ID {
		return evidence.Execution{}, evidence.ErrDenied
	}
	return s.e, s.e.Access.Authorize(ctx)
}
func (s *coverageOriginalStore) RegisterArtifact(ctx context.Context, v evidence.VerifiedArtifact) (evidence.Artifact, error) {
	a, err := v.Metadata()
	if err != nil {
		return a, err
	}
	if err = a.Access.Authorize(ctx); err != nil {
		return a, err
	}
	s.artifacts[a.ID] = a
	return a, nil
}
func (s *coverageOriginalStore) ResultArtifact(ctx context.Context, id string) (evidence.Artifact, error) {
	a, ok := s.artifacts[id]
	if !ok {
		return a, evidence.ErrDenied
	}
	return a, a.Access.Authorize(ctx)
}
func (s *coverageOriginalStore) ResultArtifacts(ctx context.Context, id string, limit, offset int) ([]evidence.Artifact, error) {
	var out []evidence.Artifact
	for _, a := range s.artifacts {
		if a.ExecutionID == id {
			out = append(out, a)
		}
	}
	return out, nil
}

func boundHTTPFixture(t *testing.T) coverage.HTTPObservation {
	t.Helper()
	root := t.TempDir()
	now := time.Now()
	input := `{"command":"curl -q -sSi https://inventory.invalid/item/0"}`
	output := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\noffline fixture"
	e := evidence.Execution{ID: "http-execution", Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "owner"}, AssessmentID: "run-a", ScopeID: "scope", Tool: "exec", Status: "completed", Completion: evidence.Complete, StartedAt: now, FinishedAt: now, OutputBytes: int64(len(output))}
	store := &coverageOriginalStore{e: e, artifacts: map[string]evidence.Artifact{}}
	ctx := evidence.WithAccess(context.Background(), e.Access)
	registry, err := evidence.NewRegistry(store, []evidence.ManagedRoot{{Path: root, Access: e.Access, ExecutionID: e.ID}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	save := func(name, kind, body string) evidence.Artifact {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		a, err := registry.Register(ctx, e, evidence.Candidate{Path: path, Kind: kind, Format: "text", Completion: evidence.Complete})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	in, out := save("input.json", "input", input), save("output.txt", "output", output)
	observation, err := coverage.VerifyHTTPOriginal(ctx, registry, coverage.OriginalBinding{Access: e.Access, AssessmentID: e.AssessmentID, ScopeID: e.ScopeID}, e.ID, in.ID, out.ID)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestCoverageBoundHTTPObservationMapsOnlyExactBaseline(t *testing.T) {
	observation := boundHTTPFixture(t)
	index := completeCoverageSources(nil, time.Now().UnixMilli())
	index.addHTTP(observation)
	index.addHTTP(observation)
	if len(index.byExecution) != 1 {
		t.Fatal("one execution counted twice")
	}
	for _, test := range []struct {
		name, family, status string
		item                 int
		want                 int
	}{
		{"bound-baseline", "http-baseline", "covered", 0, 1},
		{"other-url", "http-baseline", "covered", 1, 0},
		{"arbitrary-risk", "access-control", "covered", 0, 0},
		{"not-safe-proof", "http-baseline", "negated", 0, 0},
		{"na-only", "http-baseline", "not-applicable", 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := progressFacts(test.item, test.status, "execution:http-execution")
			facts[1].Body = strings.ReplaceAll(facts[1].Body, "access-control", test.family)
			got := inventoryDispositionFacts(facts, "run-a", index)
			if len(got) != test.want {
				t.Fatalf("mapped=%d want=%d", len(got), test.want)
			}
		})
	}
	for _, proof := range []string{"execution:http-execution", "mcp_execution:http-execution", "source:http-" + observation.OutputArtifactID()} {
		if !index.corroborates(map[string]any{"evidence": proof, "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"}) {
			t.Fatalf("exact reference rejected: %s", proof)
		}
	}
	for _, fields := range []map[string]any{
		{"evidence": "execution:http-execution-suffix", "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"},
		{"evidence": "project_fact:http-execution", "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"},
		{"execution_id": "http-execution", "endpoint_url": "https://inventory.invalid/item/0", "method": "POST"},
		{"execution_id": "http-execution", "source_id": "invented", "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"},
		{"execution_id": "http-execution-suffix", "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"},
	} {
		if index.corroborates(fields) {
			t.Fatalf("unbound fields corroborated: %v", fields)
		}
	}
	if !index.corroborates(map[string]any{"source_id": "http-" + observation.OutputArtifactID(), "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"}) {
		t.Fatal("exact source reference did not match")
	}
}

func TestCoverageStaticJSOnlyCountsDiscovery(t *testing.T) {
	for _, tool := range []string{"jsluice", "jsapiscan"} {
		index := completeCoverageSources([]database.AssessmentSourceMetadata{progressSource("static-source", "static-execution", tool)}, time.Now().UnixMilli())
		if len(index.byExecution) != 1 {
			t.Fatalf("%s not counted as discovery/analysis", tool)
		}
		fields := map[string]any{"execution_id": "static-execution", "endpoint_url": "https://inventory.invalid/item/0", "method": "GET"}
		if index.corroborates(fields) {
			t.Fatalf("%s static URL became HTTP verification", tool)
		}
		if got := inventoryDispositionFacts(progressFacts(0, "covered", "execution:static-execution"), "run-a", index); len(got) != 0 {
			t.Fatalf("%s risk promoted", tool)
		}
	}
}

// Deeper real-world risk units (SQLi, authorization, weak passwords) document
// more testing; they must never invalidate an evidenced baseline disposition.
// Only the evidenced covered baseline unit itself may dispose the candidate.
func TestCoverageBoundHTTPObservationKeepsBaselineWithDeeperRiskUnits(t *testing.T) {
	observation := boundHTTPFixture(t)
	index := completeCoverageSources(nil, time.Now().UnixMilli())
	index.addHTTP(observation)

	facts := progressFacts(0, "covered", "execution:http-execution")
	facts[1].Body = strings.ReplaceAll(facts[1].Body, "access-control", "http-baseline")

	endpointID, _ := coverage.EndpointKey("https://inventory.invalid/item/0", "GET")
	endpointKey := "recon/endpoint/run-a/" + endpointID
	sqliKey := "recon/risk/run-a/item-0-sqli"
	sqli, _ := json.Marshal(map[string]any{
		"assessment_id": "run-a", "endpoint_key": endpointKey, "risk_family": "sqli", "identity": "anonymous",
		"status": "negated", "evidence": "boolean and time probes show no differential",
	})
	var endpoint map[string]any
	if err := json.Unmarshal([]byte(facts[0].Body), &endpoint); err != nil {
		t.Fatal(err)
	}
	endpoint["risk_units"] = []string{facts[1].Key, sqliKey}
	body, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	facts[0].Body = string(body)
	facts = append(facts, coverage.Fact{Key: sqliKey, Body: string(sqli)})

	if got := inventoryDispositionFacts(facts, "run-a", index); len(got) != 1 {
		t.Fatalf("evidenced baseline invalidated by deeper risk units: mapped=%d want=1", len(got))
	}

	// Without any evidenced baseline unit the endpoint stays unresolved even
	// when other terminal risk units exist.
	facts[1].Body = strings.ReplaceAll(facts[1].Body, "http-baseline", "access-control")
	if got := inventoryDispositionFacts(facts, "run-a", index); len(got) != 0 {
		t.Fatalf("baseline-free endpoint was disposed: mapped=%d want=0", len(got))
	}
}
