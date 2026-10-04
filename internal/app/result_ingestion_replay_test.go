package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/security"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func ingestionReplayFixture(t *testing.T, db *database.DB, conversation, state string) (context.Context, evidence.Execution, *mcp.ToolExecution) {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Millisecond)
	end := start.Add(time.Second)
	e := evidence.Execution{ID: uuid.NewString(), Access: evidence.Access{Owner: "old-owner", ProjectID: "old-project", ConversationID: conversation}, AssessmentID: "old-assessment", ScopeID: "old-scope", Tool: "subfinder", Status: "completed", Completion: evidence.Complete, StartedAt: start, FinishedAt: end}
	o := &mcp.ToolExecution{ID: e.ID, OwnerUserID: e.Owner, ConversationID: conversation, ToolName: e.Tool, Status: e.Status, StartTime: start, EndTime: &end, Arguments: map[string]interface{}{"domain": "example.invalid"}, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "www.example.invalid\n"}}}}
	ctx := evidence.WithAccess(context.Background(), e.Access)
	if err := db.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveToolExecution(o); err != nil {
		t.Fatal(err)
	}
	if err := db.SetResultIngestionState(ctx, e, state, "bounded ingestion queue full; original retained, reimport required"); err != nil {
		t.Fatal(err)
	}
	return ctx, e, o
}

func TestResultPipelineSaturationPersistsEveryResultBeforeWake(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "saturated.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("saturation", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.MultiAgent.EinoMiddleware.ReductionRootDir = filepath.Join(t.TempDir(), "reduction")
	p := offlineResultPipeline(db, cfg, zap.NewNop())
	start, end := time.Now(), time.Now().Add(time.Second)
	var last string
	for i := 0; i < 130; i++ {
		last = uuid.NewString()
		// The normal monitor write has deliberately NOT run yet.
		p.observe(context.Background(), &mcp.ToolExecution{ID: last, OwnerUserID: "owner", ConversationID: conv.ID, ToolName: "subfinder", Status: "completed", StartTime: start, EndTime: &end, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "www.example.invalid\n"}}}})
	}
	var pending, originals, failed int
	if err = db.QueryRow(`SELECT COUNT(*) FROM result_ingestion_jobs WHERE state='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM result_ingestion_jobs WHERE state='failed'`).Scan(&failed)
	_ = db.QueryRow(`SELECT COUNT(*) FROM tool_executions`).Scan(&originals)
	if pending != 130 || originals != 130 || failed != 0 || len(p.wake) != 1 {
		t.Fatalf("saturation lost work: pending=%d originals=%d failed=%d wake=%d", pending, originals, failed, len(p.wake))
	}
	// A fresh pipeline can load work without the old channel or request context.
	restarted := offlineResultPipeline(db, cfg, zap.NewNop())
	claim, err := db.ClaimResultIngestion(context.Background(), last, resultIngestionLease)
	if err != nil || claim == nil {
		t.Fatalf("restart claim: %+v %v", claim, err)
	}
	if err = restarted.runClaim(context.Background(), *claim); err != nil {
		t.Fatal(err)
	}
	job, _ := db.ResultIngestionJob(context.Background(), last)
	if job.State != "complete" {
		t.Fatalf("restarted job not processed: %+v", job)
	}
}

func TestReplayResultIngestionsOnlySelected27AndNoAuthorityEscalation(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "replay.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ids := make([]string, 27)
	var first evidence.Execution
	for i := range ids {
		_, e, _ := ingestionReplayFixture(t, db, fmt.Sprintf("old-conversation-%d", i%10), "failed")
		ids[i] = e.ID
		if i == 0 {
			first = e
		}
	}
	_, excluded, _ := ingestionReplayFixture(t, db, "excluded", "failed")
	cfg := &config.Config{}
	cfg.MultiAgent.EinoMiddleware.ReductionRootDir = filepath.Join(t.TempDir(), "reduction")
	// An administrator invoking maintenance is NOT the executing user's grant.
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("operator-admin", "admin", database.RBACScopeAll, map[string]bool{"asset:write": true, "project:write": true}))
	reports, err := ReplayResultIngestions(ctx, db, cfg, zap.NewNop(), ids)
	if err != nil || len(reports) != 27 {
		t.Fatalf("recovery failed: %+v %v", reports, err)
	}
	for _, r := range reports {
		if r.State != "complete" || !r.Requeued || r.TotalAttempts != 1 || r.Owner != "old-owner" || r.ProjectID != "old-project" || r.ScopeID != "old-scope" || r.AssessmentID != "old-assessment" || !strings.Contains(r.Reason, "projection skipped") {
			t.Fatalf("false success, drifting binding or privilege: %+v", r)
		}
	}
	untouched, _ := db.ResultIngestionJob(ctx, excluded.ID)
	if untouched.State != "failed" || untouched.Attempts != 0 {
		t.Fatalf("unselected historical failure touched: %+v", untouched)
	}
	for _, table := range []string{"assets", "finding_candidates", "project_facts", "vulnerabilities"} {
		var n int
		if err = db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("legacy snapshot gained %s writes: %d %v", table, n, err)
		}
	}
	var beforeArtifacts, beforeInventory int
	_ = db.QueryRow(`SELECT COUNT(*) FROM result_artifacts`).Scan(&beforeArtifacts)
	_ = db.QueryRow(`SELECT COUNT(*) FROM recon_inventory`).Scan(&beforeInventory)
	if beforeArtifacts != 54 || beforeInventory != 10 {
		t.Fatalf("originals/inventory not actually processed: %d %d", beforeArtifacts, beforeInventory)
	}
	accessCtx := evidence.WithAccess(ctx, first.Access)
	if err = db.SetResultIngestionState(accessCtx, first, "failed", "simulate crash after imports"); err != nil {
		t.Fatal(err)
	}
	if reports, err = ReplayResultIngestions(ctx, db, cfg, zap.NewNop(), []string{first.ID}); err != nil || reports[0].State != "complete" || reports[0].TotalAttempts != 2 {
		t.Fatalf("idempotent replay failed: %+v %v", reports, err)
	}
	var artifacts, inventory int
	_ = db.QueryRow(`SELECT COUNT(*) FROM result_artifacts`).Scan(&artifacts)
	_ = db.QueryRow(`SELECT COUNT(*) FROM recon_inventory`).Scan(&inventory)
	if artifacts != beforeArtifacts || inventory != beforeInventory {
		t.Fatalf("retry duplicated imports: %d/%d => %d/%d", beforeArtifacts, beforeInventory, artifacts, inventory)
	}
}

func TestReplayResultIngestionsMissingOriginalStaysFailed(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "missing.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, e, _ := ingestionReplayFixture(t, db, "missing-result", "failed")
	if _, err = db.Exec(`DELETE FROM tool_executions WHERE id=?`, e.ID); err != nil {
		t.Fatal(err)
	}
	reports, err := ReplayResultIngestions(context.Background(), db, &config.Config{}, zap.NewNop(), []string{e.ID})
	if err == nil || len(reports) != 1 || reports[0].State != "failed" || reports[0].Attempts != 1 || !strings.Contains(reports[0].Reason, "saved_result_missing") {
		t.Fatalf("missing original was fabricated as success: %+v %v", reports, err)
	}
}

func TestResultIngestionContextRevocationAndOwnerMismatch(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "grants.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.BootstrapRBAC("test-only-hash", security.PermissionCatalog); err != nil {
		t.Fatal(err)
	}
	role, err := db.UpsertRBACRole("", "ingestion-project-writer", "", database.RBACScopeAll, []string{"project:write"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateRBACUser("ingestion-owner", "owner", "hash", true, []string{role.ID})
	if err != nil {
		t.Fatal(err)
	}
	p := offlineResultPipeline(db, &config.Config{}, zap.NewNop())
	s := database.ResultIngestionSnapshot{Execution: evidence.Execution{Access: evidence.Access{Owner: user.ID, ProjectID: "p", ConversationID: "c"}}, Projection: database.ResultIngestionProjection{Owner: user.ID, ProjectWrite: true, ProjectScope: database.RBACScopeAll, AssetWrite: true, AssetScope: database.RBACScopeAll}}
	ctx, skipped := p.ingestionContext(context.Background(), s)
	principal, _ := authctx.PrincipalFromContext(ctx)
	if skipped || !principal.HasPermission("project:write") || principal.HasPermission("asset:write") {
		t.Fatalf("historical/live permission intersection widened: %+v", principal)
	}
	disabled := false
	if err = db.UpdateRBACUser(user.ID, "owner", &disabled, nil); err != nil {
		t.Fatal(err)
	}
	ctx, skipped = p.ingestionContext(ctx, s)
	principal, _ = authctx.PrincipalFromContext(ctx)
	if !skipped || principal.HasPermission("project:write") {
		t.Fatal("disabled user retained projection authority")
	}
	s.Projection.Owner = "another-owner"
	ctx, _ = p.ingestionContext(context.Background(), s)
	principal, _ = authctx.PrincipalFromContext(ctx)
	if len(principal.Permissions) != 0 || principal.UserID != user.ID {
		t.Fatal("historical identity drift")
	}
}
