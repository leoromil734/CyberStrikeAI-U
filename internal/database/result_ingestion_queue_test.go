package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func newIngestionTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "ingestion.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func ingestionFixture() (context.Context, evidence.Execution, *mcp.ToolExecution) {
	start := time.Now().UTC().Truncate(time.Millisecond)
	end := start.Add(time.Second)
	e := evidence.Execution{ID: uuid.NewString(), Access: evidence.Access{Owner: "owner", ConversationID: "conversation", ProjectID: "project"}, AssessmentID: "assessment", ScopeID: "scope", Tool: "subfinder", Status: "completed", Completion: evidence.Complete, StartedAt: start, FinishedAt: end}
	o := &mcp.ToolExecution{ID: e.ID, OwnerUserID: e.Owner, ConversationID: e.ConversationID, ToolName: e.Tool, Status: e.Status, StartTime: start, EndTime: &end, Arguments: map[string]interface{}{"domain": "example.invalid"}, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "one.example.invalid\n"}}}}
	return evidence.WithAccess(context.Background(), e.Access), e, o
}

func TestResultIngestionPersistenceAtomicAndImmutable(t *testing.T) {
	db := newIngestionTestDB(t)
	ctx, e, original := ingestionFixture()
	// Metadata uses milliseconds, while the frozen original retains nanoseconds.
	e.StartedAt = e.StartedAt.Add(123456 * time.Nanosecond)
	e.FinishedAt = e.FinishedAt.Add(654321 * time.Nanosecond)
	original.StartTime = e.StartedAt
	original.EndTime = &e.FinishedAt
	if _, err := db.Exec(`CREATE TRIGGER fail_ingestion_snapshot BEFORE INSERT ON result_ingestion_snapshots BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.PersistResultIngestion(ctx, e, original, ResultIngestionProjection{}); err == nil {
		t.Fatal("snapshot write failure was ignored")
	}
	for _, table := range []string{"result_ingestion_jobs", "result_execution_metadata", "tool_executions"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("partial transaction in %s: %d %v", table, count, err)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER fail_ingestion_snapshot`); err != nil {
		t.Fatal(err)
	}
	if err := db.PersistResultIngestion(ctx, e, original, ResultIngestionProjection{}); err != nil {
		t.Fatal(err)
	}
	claim, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute)
	if err != nil || claim == nil {
		t.Fatalf("claim: %+v %v", claim, err)
	}
	if err := db.UpdateToolExecutionResult(e.ID, &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "a later display preview"}}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.LoadResultIngestionSnapshot(ctx, *claim)
	if err != nil || snapshot.Original == nil || snapshot.Original.Result == nil || len(snapshot.Original.Result.Content) != 1 || snapshot.Original.Result.Content[0].Text != "one.example.invalid\n" {
		t.Fatalf("immutable snapshot followed changed display result: %+v %v", snapshot, err)
	}
	if err = db.FinishResultIngestion(ctx, *claim, "complete", "", false); err != nil {
		t.Fatal(err)
	}
	if err = db.PersistResultIngestion(ctx, e, original, ResultIngestionProjection{}); err != nil {
		t.Fatal(err)
	}
	job, _ := db.ResultIngestionJob(ctx, e.ID)
	if job.State != "complete" || job.Attempts != 1 {
		t.Fatalf("duplicate observer resurrected job: %+v", job)
	}
	moved := e
	moved.ScopeID = "other-scope"
	if err = db.PersistResultIngestion(ctx, moved, original, ResultIngestionProjection{}); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("scope drift accepted: %v", err)
	}
}

func TestResultIngestionStoredSnapshotOwnerCompatibilityAndIntegrity(t *testing.T) {
	for _, mode := range []string{"legacy_owner_omitted", "explicit_owner_mismatch", "corrupt_hash"} {
		t.Run(mode, func(t *testing.T) {
			db := newIngestionTestDB(t)
			ctx, e, original := ingestionFixture()
			if err := db.PersistResultIngestion(ctx, e, original, ResultIngestionProjection{}); err != nil {
				t.Fatal(err)
			}
			s := ResultIngestionSnapshot{Execution: e, Original: original}
			var body []byte
			var err error
			if mode == "legacy_owner_omitted" {
				// Reproduce the previous encoding, which dropped OwnerUserID.
				type oldSnapshot ResultIngestionSnapshot
				body, err = json.Marshal(oldSnapshot(s))
			} else {
				if mode == "explicit_owner_mismatch" {
					s.Original.OwnerUserID = "other-owner"
				}
				body, err = json.Marshal(s)
			}
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			hash := hex.EncodeToString(sum[:])
			if mode == "corrupt_hash" {
				hash = "invalid"
			}
			if _, err = db.Exec(`UPDATE result_ingestion_snapshots SET snapshot_json=?,sha256=? WHERE execution_id=?`, string(body), hash, e.ID); err != nil {
				t.Fatal(err)
			}
			// Parsing can downgrade completeness without changing identity.
			e.Completion, e.Capped = evidence.Partial, true
			if err = db.RecordExecution(ctx, e); err != nil {
				t.Fatal(err)
			}
			claim, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute)
			if err != nil || claim == nil {
				t.Fatalf("claim: %+v %v", claim, err)
			}
			s, err = db.LoadResultIngestionSnapshot(ctx, *claim)
			switch mode {
			case "legacy_owner_omitted":
				if err != nil || s.Original == nil || s.Original.OwnerUserID != e.Owner || s.Execution.Completion != evidence.Partial || !s.Execution.Capped || s.Projection.Owner != "" {
					t.Fatalf("legacy snapshot lost identity/completeness or gained authority: %+v %v", s, err)
				}
			case "explicit_owner_mismatch":
				if !errors.Is(err, evidence.ErrDenied) {
					t.Fatalf("explicit owner mismatch accepted: %v", err)
				}
			case "corrupt_hash":
				if !errors.Is(err, evidence.ErrChanged) {
					t.Fatalf("corrupt snapshot hash accepted: %v", err)
				}
			}
		})
	}
}

func TestResultIngestionAtomicClaimAndExpiredWorkerFencing(t *testing.T) {
	db := newIngestionTestDB(t)
	ctx, e, original := ingestionFixture()
	if err := db.PersistResultIngestion(ctx, e, original, ResultIngestionProjection{}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	claims := make(chan *ResultIngestionJob, 12)
	errorsC := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claim, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute)
			if err != nil {
				errorsC <- err
			} else if claim != nil {
				claims <- claim
			}
		}()
	}
	wg.Wait()
	close(errorsC)
	for err := range errorsC {
		t.Error(err)
	}
	if len(claims) != 1 {
		t.Fatalf("want exactly one concurrent claimant, got %d", len(claims))
	}
	first := <-claims
	if err := db.ReconcileResultIngestionJobs(); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckResultIngestionLease(ctx, *first); err != nil {
		t.Fatal("startup revoked live lease", err)
	}
	if err := db.SetResultIngestionState(ctx, e, "complete", "unfenced"); err == nil {
		t.Fatal("legacy state writer stole active job")
	}
	if _, err := db.Exec(`UPDATE result_ingestion_jobs SET lease_until_ms=0 WHERE execution_id=?`, e.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.RenewResultIngestionLease(ctx, *first, time.Minute); !errors.Is(err, ErrResultIngestionLeaseLost) {
		t.Fatal("expired heartbeat revived lease", err)
	}
	second, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute)
	if err != nil || second == nil || second.Attempts != 2 || second.LeaseToken == first.LeaseToken {
		t.Fatalf("takeover: %+v %v", second, err)
	}
	if err := db.FinishResultIngestion(ctx, *first, "complete", "late success", false); !errors.Is(err, ErrResultIngestionLeaseLost) {
		t.Fatal("stale worker overwrote replacement", err)
	}
	if err := db.FinishResultIngestion(ctx, *second, "complete", "", false); err != nil {
		t.Fatal(err)
	}
}

func TestResultIngestionRetryBackoffBudgetAndExplicitRequeue(t *testing.T) {
	db := newIngestionTestDB(t)
	ctx, e, original := ingestionFixture()
	if err := db.PersistResultIngestion(ctx, e, original, ResultIngestionProjection{}); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= ResultIngestionMaxAttempts; attempt++ {
		claim, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute)
		if err != nil || claim == nil || claim.Attempts != attempt {
			t.Fatalf("attempt %d claim: %+v %v", attempt, claim, err)
		}
		if err = db.FinishResultIngestion(ctx, *claim, "failed", "injected storage failure", true); err != nil {
			t.Fatal(err)
		}
		if premature, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute); err != nil || premature != nil {
			t.Fatalf("retry did not respect backoff/ceiling: %+v %v", premature, err)
		}
		if attempt < ResultIngestionMaxAttempts {
			if _, err = db.Exec(`UPDATE result_ingestion_jobs SET next_attempt_ms=0 WHERE execution_id=?`, e.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	job, _ := db.ResultIngestionJob(ctx, e.ID)
	if job.State != "failed" || job.TotalAttempts != 5 || job.LastError != "injected storage failure" {
		t.Fatalf("failure diagnostic missing: %+v", job)
	}
	if err := db.ReconcileResultIngestionJobs(); err != nil {
		t.Fatal(err)
	}
	if claim, _ := db.ClaimResultIngestion(ctx, e.ID, time.Minute); claim != nil {
		t.Fatal("restart automatically replayed a historical failure")
	}
	moved := e
	moved.AssessmentID = "new-run"
	if err := db.RequeueResultIngestion(ctx, moved); !errors.Is(err, evidence.ErrDenied) {
		t.Fatal("requeue changed assessment", err)
	}
	if err := db.RequeueResultIngestion(ctx, e); err != nil {
		t.Fatal(err)
	}
	job, _ = db.ResultIngestionJob(ctx, e.ID)
	if job.State != "pending" || job.Attempts != 0 || job.TotalAttempts != 5 || job.LastError == "" {
		t.Fatalf("requeue fabricated success or erased history: %+v", job)
	}
}

func TestResultIngestionLegacyRecoveryAndMigration(t *testing.T) {
	db := newIngestionTestDB(t)
	ctx, e, original := ingestionFixture()
	if err := db.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveToolExecution(original); err != nil {
		t.Fatal(err)
	}
	if err := db.SetResultIngestionState(ctx, e, "pending", "legacy"); err != nil {
		t.Fatal(err)
	}
	if err := db.InitResultIngestionTables(); err != nil {
		t.Fatal(err)
	}
	if err := db.ReconcileResultIngestionJobs(); err != nil {
		t.Fatal(err)
	}
	claim, err := db.ClaimResultIngestion(ctx, e.ID, time.Minute)
	if err != nil || claim == nil {
		t.Fatalf("legacy pending not recoverable: %+v %v", claim, err)
	}
	s, err := db.LoadResultIngestionSnapshot(ctx, *claim)
	if err != nil || s.Execution.ScopeID != e.ScopeID || s.Projection.Owner != "" || s.Projection.ProjectWrite || s.Projection.AssetWrite {
		t.Fatalf("legacy recovery changed binding or invented authority: %+v %v", s, err)
	}
	if _, err = db.Exec(`UPDATE result_execution_metadata SET assessment_id='new-assessment' WHERE execution_id=?`, e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.LoadResultIngestionSnapshot(ctx, *claim); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("worker followed changed assessment: %v", err)
	}
}

func TestResultIngestionAdditiveOldSchemaMigration(t *testing.T) {
	db := newIngestionTestDB(t)
	if _, err := db.Exec(`DROP TABLE result_ingestion_jobs`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE result_ingestion_jobs (execution_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,conversation_id TEXT NOT NULL,owner TEXT NOT NULL,assessment_id TEXT NOT NULL,scope_id TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',updated_at_ms BIGINT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO result_ingestion_jobs VALUES('old','p','c','u','a','s','failed','queue full',1)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := db.InitResultIngestionTables(); err != nil {
			t.Fatal(err)
		}
	}
	job, err := db.ResultIngestionJob(context.Background(), "old")
	if err != nil || job.State != "failed" || job.Reason != "queue full" || job.Attempts != 0 || job.LeaseToken != "" || job.LeaseUntilMS != 0 {
		t.Fatalf("migration changed historical failure: %+v %v", job, err)
	}
}

func TestResultIngestionCandidateReplayPreservesDecision(t *testing.T) {
	db := newIngestionTestDB(t)
	project, err := db.CreateProject(&Project{Name: "ingestion"})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("ingestion", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	_, e, _ := ingestionFixture()
	e.ProjectID, e.ConversationID = project.ID, conversation.ID
	ctx := evidence.WithAccess(context.Background(), e.Access)
	candidate := &FindingCandidate{ProjectID: e.ProjectID, ConversationID: e.ConversationID, AssessmentID: e.AssessmentID, Target: "example.invalid", Title: "scanner hit", RiskFamily: "scanner_match", Status: "tentative"}
	if err = db.ImportResultIngestionCandidate(ctx, e, candidate, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE finding_candidates SET status='rejected',reason='human decision' WHERE project_id=?`, e.ProjectID); err != nil {
		t.Fatal(err)
	}
	if err = db.ImportResultIngestionCandidate(ctx, e, candidate, nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM finding_candidates WHERE project_id=? AND status='rejected' AND reason='human decision'`, e.ProjectID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay reverted a human candidate decision: %d %v", count, err)
	}
}
