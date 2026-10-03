package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testStore struct {
	executions map[string]Execution
	artifacts  map[string]Artifact
}

func newTestStore() *testStore { return &testStore{map[string]Execution{}, map[string]Artifact{}} }
func (s *testStore) RecordExecution(ctx context.Context, e Execution) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	if previous, ok := s.executions[e.ID]; ok && previous.Access != e.Access {
		return ErrDenied
	}
	s.executions[e.ID] = e
	return nil
}
func (s *testStore) ResultExecution(ctx context.Context, id string) (Execution, error) {
	e, ok := s.executions[id]
	if !ok {
		return Execution{}, ErrDenied
	}
	if err := e.Access.Authorize(ctx); err != nil {
		return Execution{}, err
	}
	return e, nil
}
func (s *testStore) RegisterArtifact(ctx context.Context, v VerifiedArtifact) (Artifact, error) {
	a, err := v.Metadata()
	if err != nil {
		return a, err
	}
	if _, err = s.ResultExecution(ctx, a.ExecutionID); err != nil {
		return Artifact{}, err
	}
	s.artifacts[a.ID] = a
	return a, nil
}
func (s *testStore) ResultArtifact(ctx context.Context, id string) (Artifact, error) {
	a, ok := s.artifacts[id]
	if !ok {
		return Artifact{}, ErrDenied
	}
	if err := a.Access.Authorize(ctx); err != nil {
		return Artifact{}, err
	}
	return a, nil
}
func (s *testStore) ResultArtifacts(ctx context.Context, id string, limit, offset int) ([]Artifact, error) {
	if _, err := s.ResultExecution(ctx, id); err != nil {
		return nil, err
	}
	var out []Artifact
	for _, a := range s.artifacts {
		if a.ExecutionID == id {
			out = append(out, a)
		}
	}
	return out, nil
}

func evidenceFixture(t *testing.T) (context.Context, Execution, *Registry, string) {
	t.Helper()
	root := t.TempDir()
	store := newTestStore()
	e := Execution{ID: "exec-1", Access: Access{ProjectID: "p1", ConversationID: "c1", Owner: "u1"}, Tool: "httpx", ScopeID: "scope1", AssessmentID: "assessment1", Status: "completed", Completion: Complete, FinishedAt: time.Now()}
	ctx := WithAccess(context.Background(), e.Access)
	if err := store.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(store, []ManagedRoot{{Path: root, Access: e.Access, ExecutionID: e.ID}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return ctx, e, registry, root
}

func writeOriginal(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRejectsPathEscapeArbitraryAndUnboundExecution(t *testing.T) {
	ctx, e, r, root := evidenceFixture(t)
	inside := filepath.Join(root, "out.txt")
	writeOriginal(t, inside, "observed output")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeOriginal(t, outside, "outside")
	for _, path := range []string{outside, "out.txt", filepath.Join(root, "child") + string(filepath.Separator) + ".." + string(filepath.Separator) + "out.txt", root, inside + ":stream"} {
		if _, err := r.Register(ctx, e, Candidate{Path: path, Kind: "output", Format: "text", Completion: Complete}); err == nil {
			t.Errorf("unsafe path accepted: %q", path)
		}
	}
	other := e
	other.ID = "exec-other"
	if err := r.store.RecordExecution(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, other, Candidate{Path: inside, Kind: "output", Format: "text", Completion: Complete}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("execution-bound root: %v", err)
	}
	if _, err := r.store.RegisterArtifact(ctx, VerifiedArtifact{}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("forged token: %v", err)
	}
}

func TestEvidenceSymlinkRefused(t *testing.T) {
	ctx, e, r, root := evidenceFixture(t)
	file := filepath.Join(root, "real.txt")
	writeOriginal(t, file, "data")
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("platform cannot create symlinks: %v", err)
	}
	if _, err := r.Register(ctx, e, Candidate{Path: link, Kind: "output", Format: "text", Completion: Complete}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink accepted: %v", err)
	}
	outside := t.TempDir()
	writeOriginal(t, filepath.Join(outside, "data.txt"), "outside")
	directoryLink := filepath.Join(root, "dirlink")
	if err := os.Symlink(outside, directoryLink); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, e, Candidate{Path: filepath.Join(directoryLink, "data.txt"), Kind: "output", Format: "text", Completion: Complete}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("directory symlink accepted: %v", err)
	}
}

func TestEvidenceHashBoundedReadAndCrossProject(t *testing.T) {
	ctx, e, r, root := evidenceFixture(t)
	file := filepath.Join(root, "out.txt")
	writeOriginal(t, file, "0123456789 actual output")
	a, err := r.Register(ctx, e, Candidate{Path: file, Kind: "output", Format: "text", Completion: Complete})
	if err != nil {
		t.Fatal(err)
	}
	if a.Size != 24 || len(a.SHA256) != 64 {
		t.Fatalf("wrong metadata: %+v", a)
	}
	snippet, err := r.ReadRegion(ctx, e.ID, Region{ArtifactID: a.ID, Offset: 3, Length: 4})
	if err != nil || snippet.Text != "3456" || !snippet.Truncated {
		t.Fatalf("bounded read: %+v %v", snippet, err)
	}
	if _, err = r.ReadRegion(ctx, "another-execution", Region{ArtifactID: a.ID}); !errors.Is(err, ErrDenied) {
		t.Fatalf("cross-execution read: %v", err)
	}
	for _, foreign := range []Access{{ProjectID: "p2", ConversationID: e.ConversationID, Owner: e.Owner}, {ProjectID: e.ProjectID, ConversationID: "c2", Owner: e.Owner}, {ProjectID: e.ProjectID, ConversationID: e.ConversationID, Owner: "u2"}} {
		if _, err = r.ReadRegion(WithAccess(ctx, foreign), e.ID, Region{ArtifactID: a.ID}); !errors.Is(err, ErrDenied) {
			t.Fatalf("foreign binding accepted: %v", err)
		}
	}
	for _, region := range []Region{{ArtifactID: a.ID, Offset: -1}, {ArtifactID: a.ID, Length: MaxEvidenceBytes + 1}, {ArtifactID: a.ID, Offset: 1000}} {
		if _, err = r.ReadRegion(ctx, e.ID, region); !errors.Is(err, ErrLimit) {
			t.Fatalf("range limit ignored: %v", err)
		}
	}
	if _, err = r.Register(ctx, e, Candidate{Path: file, Kind: "output", Format: "text", Completion: Complete, ExpectedSHA256: strings.Repeat("0", 64)}); !errors.Is(err, ErrChanged) {
		t.Fatalf("declared hash trusted: %v", err)
	}
	writeOriginal(t, file, "0123456789 CHANGED output")
	if _, _, err = r.OpenVerified(ctx, a.ID); !errors.Is(err, ErrChanged) {
		t.Fatalf("changed original accepted: %v", err)
	}
}

func TestEvidenceMinimalInputOutputRedactsAndNeverVerifies(t *testing.T) {
	ctx, e, r, root := evidenceFixture(t)
	input := filepath.Join(root, "input.txt")
	output := filepath.Join(root, "output.txt")
	writeOriginal(t, input, "GET /users/42?token=secret-value\nAuthorization: Bearer another-secret\n")
	writeOriginal(t, output, "HTTP/1.1 200 OK\nCookie: session=secret-cookie\nactual body\n")
	in, err := r.Register(ctx, e, Candidate{Path: input, Kind: "input", Format: "text", Completion: Complete})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Register(ctx, e, Candidate{Path: output, Kind: "output", Format: "text", Completion: Partial})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := r.Assemble(ctx, e.ID, Region{ArtifactID: in.ID}, Region{ArtifactID: out.ID})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Verification != "unverified" || !bundle.Input.Redacted || !bundle.Output.Redacted || !strings.Contains(bundle.Text, "actual body") || strings.Contains(bundle.Text, "secret-value") || strings.Contains(bundle.Text, "another-secret") || strings.Contains(bundle.Text, "secret-cookie") {
		t.Fatalf("unsafe bundle: %+v", bundle)
	}
	if _, err = r.Assemble(ctx, e.ID, Region{ArtifactID: out.ID}, Region{ArtifactID: in.ID}); !errors.Is(err, ErrDenied) {
		t.Fatalf("roles not enforced: %v", err)
	}
}

func TestEvidencePartialAndOversizedOriginal(t *testing.T) {
	ctx, e, r, root := evidenceFixture(t)
	e.TimedOut = true
	e.Completion = Partial
	if err := r.store.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "partial.txt")
	writeOriginal(t, file, "partial actual data")
	a, err := r.Register(ctx, e, Candidate{Path: file, Kind: "output", Format: "text", Completion: Complete})
	if err != nil || a.Completion != Partial {
		t.Fatalf("timeout completeness: %+v %v", a, err)
	}
	large := filepath.Join(root, "large.txt")
	writeOriginal(t, large, strings.Repeat("x", (1<<20)+1))
	if _, err = r.Register(ctx, e, Candidate{Path: large, Kind: "output", Format: "text", Completion: Complete}); !errors.Is(err, ErrLimit) {
		t.Fatalf("artifact size limit: %v", err)
	}
}

func TestEvidenceHardLinkAliasesRefused(t *testing.T) {
	ctx, e, r, root := evidenceFixture(t)
	file := filepath.Join(root, "real.txt")
	writeOriginal(t, file, "data")
	link := filepath.Join(root, "hardlink.txt")
	if err := os.Link(file, link); err != nil {
		t.Skipf("platform cannot create hard links: %v", err)
	}
	if _, err := r.Register(ctx, e, Candidate{Path: link, Kind: "output", Format: "text", Completion: Complete}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hard-link alias accepted: %v", err)
	}
}

func TestEvidenceReductionExactExecutionAllowlist(t *testing.T) {
	ctx, e, _, _ := evidenceFixture(t)
	base := t.TempDir()
	e.ID = "execution"
	root, err := ReductionRoot(base, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root.Path, 0700); err != nil {
		t.Fatal(err)
	}
	store := newTestStore()
	if err = store.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(store, []ManagedRoot{root}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	other := filepath.Join(root.Path, "unrelated")
	writeOriginal(t, other, "not this execution")
	if _, err = r.Register(ctx, e, Candidate{Path: other, Kind: "output", Format: "text", Completion: Complete}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("spill allowlist: %v", err)
	}
	e.ID = "../invalid"
	if _, err = ReductionRoot(base, e); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("unsafe spill identifier: %v", err)
	}
}
