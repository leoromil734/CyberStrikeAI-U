package experience

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	em "cyberstrike-ai/internal/experience/model"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func experienceFixture(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "memory.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, zap.NewNop()), db
}
func memoryContext(user, scope string) context.Context {
	permissions := map[string]bool{"experience:read": true, "experience:write": true, "monitor:read": true, "project:read": true}
	if scope == database.RBACScopeAll {
		permissions["experience:review"] = true
		permissions["experience:share"] = true
		permissions["experience:export"] = true
	}
	return authctx.WithPrincipal(context.Background(), authctx.NewPrincipal(user, user, scope, permissions))
}
func evidenceExecution(t *testing.T, db *database.DB, id, owner, status, errorText string) {
	t.Helper()
	now := time.Now()
	end := now.Add(time.Second)
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: id, ToolName: "scanner", OwnerUserID: owner, Status: status, Error: errorText, StartTime: now, EndTime: &end, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "actual result"}}, IsError: status != mcp.ToolExecutionStatusCompleted}}); err != nil {
		t.Fatal(err)
	}
}
func methodProposal(exec string) em.Proposal {
	return em.Proposal{Content: em.Content{Kind: em.KindVulnerability, Title: "Framework-A validation", Summary: "conditional verification procedure", Conditions: em.Conditions{Product: "framework-a", Versions: []string{"1.2.3"}, Required: map[string]string{"auth": "anonymous"}}, Steps: []string{"Compare authorized {{target}} with baseline"}, Verification: "confirm observed boundary difference", Artifacts: []em.Artifact{{Name: "method.txt", Content: "parameterized validation instructions"}}}, Evidence: []em.Evidence{{ExecutionID: exec, Role: "validation"}}}
}
func TestExperienceSearchRequiresReviewAndMatchingKnownVersion(t *testing.T) {
	s, db := experienceFixture(t)
	evidenceExecution(t, db, "proof", "u1", mcp.ToolExecutionStatusCompleted, "")
	ctx := memoryContext("u1", database.RBACScopeOwn)
	e, err := s.Propose(ctx, methodProposal("proof"))
	if err != nil {
		t.Fatal(err)
	}
	q := em.Search{Product: "framework-a", Version: "1.2.3", Facts: map[string]string{"auth": "anonymous"}}
	if matches, err := s.Search(ctx, q); err != nil || len(matches) != 0 {
		t.Fatalf("candidate was recalled: %v, %v", matches, err)
	}
	if err := s.Review(ctx, e.ID, em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "self-reviewed"}); !errors.Is(err, ErrDenied) {
		t.Fatal("ordinary user could self-verify")
	}
	admin := memoryContext("admin", database.RBACScopeAll)
	if err := s.Review(admin, e.ID, em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "execution and baseline checked"}); err != nil {
		t.Fatal(err)
	}
	other := memoryContext("u2", database.RBACScopeOwn)
	if matches, err := s.Search(other, q); err != nil || len(matches) != 1 {
		t.Fatalf("verified shared experience not found: %v, %v", matches, err)
	}
	q.Version = ""
	if matches, err := s.Search(other, q); err != nil || len(matches) != 0 {
		t.Fatal("unknown version matched a constrained method")
	}
	q.Version = "1.2.4"
	if matches, err := s.Search(other, q); err != nil || len(matches) != 0 {
		t.Fatal("unverified version matched")
	}
	q.Version = "1.2.3"
	q.Facts = nil
	if matches, err := s.Search(other, q); err != nil || len(matches) != 0 {
		t.Fatal("missing prerequisite matched")
	}
	d, err := s.Get(other, e.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Evidence) != 0 {
		t.Fatal("foreign private execution IDs leaked")
	}
}
func TestExperienceEvidenceSurvivesMonitorCleanupAndStaysPrivate(t *testing.T) {
	s, db := experienceFixture(t)
	evidenceExecution(t, db, "proof", "u1", mcp.ToolExecutionStatusCompleted, "")
	owner := memoryContext("u1", database.RBACScopeOwn)
	e, err := s.Propose(owner, methodProposal("proof"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM tool_executions WHERE id = 'proof'`); err != nil {
		t.Fatal(err)
	}
	admin := memoryContext("admin", database.RBACScopeAll)
	if err := s.Review(admin, e.ID, em.Review{Revision: e.Revision, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "archived proof and baseline checked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Evidence(owner, e.ID, "proof", ""); err != nil {
		t.Fatalf("owner lost archived evidence: %v", err)
	}
	if _, err := s.Evidence(memoryContext("u2", database.RBACScopeOwn), e.ID, "proof", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("shared memory granted private evidence access")
	}
	if _, err := db.Exec(`UPDATE experience_execution_archives SET snapshot_json = '{}' WHERE execution_id = 'proof'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Evidence(owner, e.ID, "proof", ""); err == nil {
		t.Fatal("tampered evidence passed integrity check")
	}
}

func TestExperienceWriteScopeDoesNotWidenFromGlobalRead(t *testing.T) {
	s, db := experienceFixture(t)
	evidenceExecution(t, db, "proof", "u1", mcp.ToolExecutionStatusCompleted, "")
	e, err := s.Propose(memoryContext("u1", database.RBACScopeOwn), methodProposal("proof"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Review(memoryContext("admin", database.RBACScopeAll), e.ID, em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "reviewed"}); err != nil {
		t.Fatal(err)
	}
	permissions := map[string]bool{"experience:read": true, "experience:write": true, "monitor:read": true}
	p := authctx.NewPrincipalWithScopes("u2", "Mixed", database.RBACScopeAll, permissions, map[string]string{"experience:read": database.RBACScopeAll, "experience:write": database.RBACScopeOwn, "monitor:read": database.RBACScopeAll})
	ctx := authctx.WithPrincipal(context.Background(), p)
	proposal := methodProposal("proof")
	proposal.Content.Summary = "attempted foreign overwrite"
	if _, err := s.Revise(ctx, e.ID, 1, proposal); !errors.Is(err, ErrDenied) {
		t.Fatalf("global read widened own write scope: %v", err)
	}
}

func TestExperienceRejectsForeignEvidenceAndUntrustedAgentSuccess(t *testing.T) {
	s, db := experienceFixture(t)
	evidenceExecution(t, db, "foreign", "u2", mcp.ToolExecutionStatusCompleted, "")
	ctx := memoryContext("u1", database.RBACScopeOwn)
	if _, err := s.Propose(ctx, methodProposal("foreign")); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign evidence accepted: %v", err)
	}
	evidenceExecution(t, db, "own", "u1", mcp.ToolExecutionStatusCompleted, "")
	e, err := s.Propose(ctx, methodProposal("own"))
	if err != nil {
		t.Fatal(err)
	}
	o := em.Outcome{EntryID: e.ID, Revision: 1, ExecutionID: "own", Result: "success", Note: "LLM says success", Environment: em.Search{Product: "framework-a", Version: "1.2.3", Facts: map[string]string{"auth": "anonymous"}}}
	if err := s.Outcome(ctx, o, false); !errors.Is(err, ErrDenied) {
		t.Fatal("model claim increased success statistics")
	}
}
func TestExperienceSharingChecksArtifactsParametersAndReferenceCredentials(t *testing.T) {
	clean := methodProposal("proof").Content
	clean.Steps = []string{"verify https://{{target}} with {{credential}}"}
	clean.Sources = []string{"https://docs.example.org/advisory"}
	if err := ValidateSharedContent(clean); err != nil {
		t.Fatal(err)
	}
	cases := []em.Content{}
	c := clean
	c.Title = "customer https://client.example.org"
	cases = append(cases, c)
	c = clean
	c.Parameters = map[string]string{"password": "admin"}
	cases = append(cases, c)
	c = clean
	c.Artifacts = []em.Artifact{{Name: "proof.txt", Content: "Authorization: Bearer sensitive-secret"}}
	cases = append(cases, c)
	c = clean
	c.Artifacts = []em.Artifact{{Name: "proof.txt", Content: `{"password":"sensitive-secret"}`}}
	cases = append(cases, c)
	c = clean
	c.Sources = []string{"https://user:password@docs.example.org"}
	cases = append(cases, c)
	c = clean
	c.Sources = []string{"https://docs.example.org/advisory?token=secret"}
	cases = append(cases, c)
	c = clean
	c.Cleanup = "remove file on 192.0.2.20"
	cases = append(cases, c)
	for i, c := range cases {
		if ValidateSharedContent(c) == nil {
			t.Errorf("unsafe shared content accepted: case %d", i)
		}
	}
}
func TestExperienceExportProducesVersionedPackageWithoutHostPaths(t *testing.T) {
	s, db := experienceFixture(t)
	evidenceExecution(t, db, "proof", "u1", mcp.ToolExecutionStatusCompleted, "")
	e, err := s.Propose(memoryContext("u1", database.RBACScopeOwn), methodProposal("proof"))
	if err != nil {
		t.Fatal(err)
	}
	admin := memoryContext("admin", database.RBACScopeAll)
	if _, _, err := s.ExportSkill(admin, e.ID, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("candidate export allowed")
	}
	if err := s.Review(admin, e.ID, em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopePrivate, Note: "proof checked"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ExportSkill(admin, e.ID, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("export allowed before independent reuse")
	}
	for _, id := range []string{"reuse-first", "reuse-second"} {
		conversation, err := db.CreateConversation(id, database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}
		evidenceExecution(t, db, id, "u1", mcp.ToolExecutionStatusCompleted, "")
		if _, err := db.Exec(`UPDATE tool_executions SET conversation_id = ? WHERE id = ?`, conversation.ID, id); err != nil {
			t.Fatal(err)
		}
		outcome := em.Outcome{EntryID: e.ID, Revision: e.Revision, ExecutionID: id, Result: "success", Note: "reviewer checked independent task output and baseline", Environment: em.Search{Product: "framework-a", Version: "1.2.3", Facts: map[string]string{"auth": "anonymous"}}}
		if err := s.Outcome(admin, outcome, true); err != nil {
			t.Fatal(err)
		}
	}
	b, name, err := s.ExportSkill(admin, e.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(name, "-r1.zip") {
		t.Fatal("export lacks revision")
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("unexpected package entries: %d", len(zr.File))
	}
	for _, file := range zr.File {
		if strings.Contains(file.Name, "..") || strings.HasPrefix(file.Name, "/") {
			t.Fatal("unsafe archive path")
		}
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(file.Name, "SKILL.md") && !strings.Contains(string(content), e.ContentHash) {
			t.Fatal("manifest lacks provenance hash")
		}
	}
}
func TestExperienceToolDefinitionChangesInvalidateRecallAndHints(t *testing.T) {
	s, db := experienceFixture(t)
	db.RegisterExperienceToolDefinition(mcp.Tool{Name: "scanner", InputSchema: map[string]interface{}{"version": "one"}})
	evidenceExecution(t, db, "failed", "u1", mcp.ToolExecutionStatusFailed, "unknown flag --old")
	evidenceExecution(t, db, "fixed", "u1", mcp.ToolExecutionStatusCompleted, "")
	p := em.Proposal{Content: em.Content{Kind: em.KindToolRepair, Title: "scanner repair", Summary: "fix argument format", Conditions: em.Conditions{ToolName: "scanner"}, Steps: []string{"use the correct parameter shape"}, Verification: "verify structured results"}, Evidence: []em.Evidence{{ExecutionID: "failed", Role: "failed"}, {ExecutionID: "fixed", Role: "corrected"}}}
	e, err := s.Propose(memoryContext("u1", database.RBACScopeOwn), p)
	if err != nil {
		t.Fatal(err)
	}
	if e.Content.Conditions.ToolSchemaHash == "" || e.Content.Conditions.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatal("missing tool/environment conditions")
	}
	admin := memoryContext("admin", database.RBACScopeAll)
	if err := s.Review(admin, e.ID, em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "calls and output checked"}); err != nil {
		t.Fatal(err)
	}
	ctx := memoryContext("u2", database.RBACScopeOwn)
	if hints := s.ToolHints(ctx, []mcp.Tool{{Name: "scanner"}}); !strings.Contains(hints, e.ID) {
		t.Fatal("verified repair was not proactively surfaced")
	}
	if hints := s.ToolHints(ctx, []mcp.Tool{{Name: "other"}}); hints != "" {
		t.Fatal("role tool restrictions ignored")
	}
	db.RegisterExperienceToolDefinition(mcp.Tool{Name: "scanner", InputSchema: map[string]interface{}{"version": "two"}})
	if hints := s.ToolHints(ctx, []mcp.Tool{{Name: "scanner"}}); hints != "" {
		t.Fatal("stale tool repair still surfaced")
	}
	matches, err := s.Search(ctx, em.Search{ToolName: "scanner", ToolSchemaHash: e.Content.Conditions.ToolSchemaHash})
	if err != nil || len(matches) != 0 {
		t.Fatal("caller could forge the old current schema")
	}
}
func TestExperienceAgentCannotReadCandidatesOrPublish(t *testing.T) {
	s, db := experienceFixture(t)
	server := mcp.NewServer(zap.NewNop())
	RegisterTools(server, s)
	server.SetToolAuthorizer(func(context.Context, string, map[string]interface{}) error { return nil })
	evidenceExecution(t, db, "proof", "u1", mcp.ToolExecutionStatusCompleted, "")
	ctx := memoryContext("u1", database.RBACScopeOwn)
	e, err := s.Propose(ctx, methodProposal("proof"))
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := server.CallTool(ctx, builtin.ToolGetExperience, map[string]interface{}{"id": e.ID})
	if err != nil || !result.IsError {
		t.Fatal("agent received unreviewed candidate")
	}
	if server.HasTool("review_experience") || server.HasTool("share_experience") {
		t.Fatal("publishing tool exposed to model")
	}
}
func TestExperienceTransientFailuresDoNotDeprecateMethods(t *testing.T) {
	s, db := experienceFixture(t)
	evidenceExecution(t, db, "proof", "u1", mcp.ToolExecutionStatusCompleted, "")
	e, err := s.Propose(memoryContext("u1", database.RBACScopeOwn), methodProposal("proof"))
	if err != nil {
		t.Fatal(err)
	}
	evidenceExecution(t, db, "timeout", "u1", mcp.ToolExecutionStatusFailed, "network timeout")
	o := em.Outcome{EntryID: e.ID, Revision: 1, ExecutionID: "timeout", Result: "failure", Note: "transient failure", Environment: em.Search{Product: "framework-a", Version: "1.2.3", Facts: map[string]string{"auth": "anonymous"}}}
	if err := s.Outcome(memoryContext("admin", database.RBACScopeAll), o, true); !errors.Is(err, ErrInvalid) {
		t.Fatal("network error counted as method failure")
	}
}
