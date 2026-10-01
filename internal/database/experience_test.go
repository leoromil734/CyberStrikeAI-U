package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	em "cyberstrike-ai/internal/experience/model"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func memoryProposal() em.Proposal {
	return em.Proposal{Content: em.Content{Kind: em.KindWorkflow, Title: "repeatable validation", Summary: "reviewed method with explicit checks", Steps: []string{"check {{target}} with current authorization"}, Verification: "compare expected behavior with baseline"}}
}
func TestExperienceVisibilityAndDeduplication(t *testing.T) {
	db := newRBACTestDB(t)
	p := memoryProposal()
	e, err := db.CreateExperience("u1", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetExperience(e.ID, ExperienceAccess{UserID: "u2"}); !errors.Is(err, ErrExperienceNotFound) {
		t.Fatalf("private experience leaked: %v", err)
	}
	if _, err := db.GetExperience(e.ID, ExperienceAccess{Global: true}); !errors.Is(err, ErrExperienceNotFound) {
		t.Fatal("anonymous global access did not fail closed")
	}
	r := em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "reviewed"}
	if err := db.ReviewExperience(e.ID, "admin", r); err != nil {
		t.Fatal(err)
	}
	again, err := db.CreateExperience("u1", p)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != e.ID || again.Status != em.StatusVerified || again.Scope != em.ScopeShared {
		t.Fatal("deduplication replaced review or publication")
	}
	if _, err := db.GetExperience(e.ID, ExperienceAccess{UserID: "u2"}); err != nil {
		t.Fatal(err)
	}
	if err := db.ReviewExperience(e.ID, "admin", em.Review{Revision: 1, Status: em.StatusDeprecated, Scope: em.ScopeShared, Note: "deprecated"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetExperience(e.ID, ExperienceAccess{UserID: "u2"}); !errors.Is(err, ErrExperienceNotFound) {
		t.Fatal("deprecated shared content still visible")
	}
}
func TestExperienceRevisionResetsTrustAndRetainsHistory(t *testing.T) {
	db := newRBACTestDB(t)
	p := memoryProposal()
	e, err := db.CreateExperience("u1", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReviewExperience(e.ID, "admin", em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared, Note: "reviewed"}); err != nil {
		t.Fatal(err)
	}
	p.Content.Steps = []string{"new procedure requiring review"}
	next, err := db.ReviseExperience(e.ID, "u1", 1, p)
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision != 2 || next.Status != em.StatusCandidate || next.Scope != em.ScopePrivate {
		t.Fatal("new revision inherited trust")
	}
	if _, err := db.ReviseExperience(e.ID, "u1", 1, p); !errors.Is(err, ErrExperienceConflict) {
		t.Fatal("stale update did not fail")
	}
	if err := db.ReviewExperience(e.ID, "admin", em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopeShared}); !errors.Is(err, ErrExperienceConflict) {
		t.Fatal("stale review succeeded")
	}
	history, err := db.ExperienceRevisionHistory(e.ID)
	if err != nil || len(history) != 2 {
		t.Fatalf("history = %v, error %v", history, err)
	}
}
func TestExperienceOutcomeIdempotencyAndFailureReview(t *testing.T) {
	db := newRBACTestDB(t)
	e, err := db.CreateExperience("u1", memoryProposal())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReviewExperience(e.ID, "admin", em.Review{Revision: 1, Status: em.StatusVerified, Scope: em.ScopePrivate, Note: "reviewed"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		saveMemoryExecution(t, db, fmt.Sprintf("failed-%d", i), "u1", "c1", mcp.ToolExecutionStatusFailed, "validation failed", nil, time.Now())
		o := em.Outcome{ID: fmt.Sprintf("outcome-%d", i), EntryID: e.ID, Revision: 1, ExecutionID: fmt.Sprintf("failed-%d", i), Result: "failure", Note: "verified real failure"}
		if err := db.SaveExperienceOutcome("u1", o); err != nil {
			t.Fatal(err)
		}
		o.ID += "-duplicate"
		if err := db.SaveExperienceOutcome("another-reviewer", o); err != nil {
			t.Fatal(err)
		}
	}
	current, err := db.GetExperience(e.ID, ExperienceAccess{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if current.Failures != 3 || current.Status != em.StatusReview {
		t.Fatalf("outcomes duplicated or publication remained: %#v", current)
	}
}
func saveMemoryExecution(t *testing.T, db *DB, id, owner, conversation, status, errorText string, args map[string]interface{}, start time.Time) *mcp.ToolExecution {
	t.Helper()
	end := start.Add(time.Second)
	e := &mcp.ToolExecution{ID: id, ToolName: "scanner", OwnerUserID: owner, ConversationID: conversation, Status: status, Error: errorText, Arguments: args, StartTime: start, EndTime: &end, Result: &mcp.ToolResult{IsError: status == mcp.ToolExecutionStatusFailed, Content: []mcp.Content{{Type: "text", Text: "bounded actual output"}}}}
	if err := db.SaveToolExecution(e); err != nil {
		t.Fatal(err)
	}
	return e
}
func enableMemoryLearning(db *DB) {
	db.SetExperienceLearningEnabled(true)
	db.RegisterExperienceToolDefinition(mcp.Tool{Name: "scanner", InputSchema: map[string]interface{}{"type": "object", "version": "one"}})
}
func TestExperienceLearningIsPrivateSanitizedAndIdempotent(t *testing.T) {
	db := newRBACTestDB(t)
	enableMemoryLearning(db)
	now := time.Now().UTC()
	saveMemoryExecution(t, db, "bad", "u1", "c1", mcp.ToolExecutionStatusFailed, "unknown flag --old", map[string]interface{}{"args": "--old https://customer.invalid", "token": "private-token"}, now)
	saveMemoryExecution(t, db, "fixed", "u1", "c1", mcp.ToolExecutionStatusCompleted, "", map[string]interface{}{"args": "--new https://customer.invalid", "token": "private-token"}, now.Add(2*time.Second))
	if _, err := db.ProcessExperienceEvents(context.Background(), 25); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ProcessExperienceEvents(context.Background(), 25); err != nil {
		t.Fatal(err)
	}
	entries, err := db.ListExperiences(ExperienceAccess{UserID: "u1"}, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Status != em.StatusCandidate || entries[0].Scope != em.ScopePrivate {
		t.Fatalf("unexpected learned entries: %#v", entries)
	}
	b, _ := json.Marshal(entries[0].Content)
	for _, private := range []string{"customer.invalid", "private-token"} {
		if strings.Contains(string(b), private) {
			t.Fatalf("private data leaked into candidate: %s", b)
		}
	}
	evidence, err := db.ExperienceEvidence(entries[0].ID, 1)
	if err != nil || len(evidence) != 2 {
		t.Fatalf("evidence = %v, error %v", evidence, err)
	}
}
func TestExperienceLearningDoesNotPairDifferentTasksOrTransientFailures(t *testing.T) {
	cases := []struct {
		name, owner, conversation, errorText string
		delay                                time.Duration
	}{
		{"other user", "u2", "c1", "unknown flag --old", 2 * time.Second},
		{"other task", "u1", "c2", "unknown flag --old", 2 * time.Second},
		{"network", "u1", "c1", "network timeout with invalid argument", 2 * time.Second},
		{"permission", "u1", "c1", "permission denied", 2 * time.Second},
		{"too old", "u1", "c1", "unknown flag --old", 20 * time.Minute},
		{"overlapping", "u1", "c1", "unknown flag --old", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newRBACTestDB(t)
			enableMemoryLearning(db)
			now := time.Now().UTC()
			saveMemoryExecution(t, db, "bad", "u1", "c1", mcp.ToolExecutionStatusFailed, tc.errorText, map[string]interface{}{"args": "--old"}, now)
			saveMemoryExecution(t, db, "fixed", tc.owner, tc.conversation, mcp.ToolExecutionStatusCompleted, "", map[string]interface{}{"args": "--new"}, now.Add(tc.delay))
			if _, err := db.ProcessExperienceEvents(context.Background(), 25); err != nil {
				t.Fatal(err)
			}
			entries, err := db.ListExperiences(ExperienceAccess{UserID: "admin", Global: true}, "", "", "", 50, 0)
			if err != nil || len(entries) != 0 {
				t.Fatalf("incorrect repair learned: %v, %v", entries, err)
			}
		})
	}
}
func TestExperienceEventAndExecutionCommitAtomically(t *testing.T) {
	db := newRBACTestDB(t)
	enableMemoryLearning(db)
	if _, err := db.Exec(`DROP TABLE experience_learning_events`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	end := now.Add(time.Second)
	err := db.SaveToolExecution(&mcp.ToolExecution{ID: "rollback", ToolName: "scanner", OwnerUserID: "u1", ConversationID: "c1", Status: mcp.ToolExecutionStatusCompleted, StartTime: now, EndTime: &end})
	if err == nil {
		t.Fatal("broken outbox unexpectedly committed")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tool_executions WHERE id = 'rollback'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("execution committed without learning event")
	}
}
func TestExperienceFingerprintFrozenAtExecutionStart(t *testing.T) {
	db := newRBACTestDB(t)
	enableMemoryLearning(db)
	original := db.ExperienceToolFingerprint("scanner")
	e := &mcp.ToolExecution{ID: "started", ToolName: "scanner", OwnerUserID: "u1", ConversationID: "c1", Status: mcp.ToolExecutionStatusRunning, StartTime: time.Now()}
	if err := db.SaveToolExecution(e); err != nil {
		t.Fatal(err)
	}
	db.RegisterExperienceToolDefinition(mcp.Tool{Name: "scanner", InputSchema: map[string]interface{}{"type": "object", "version": "two"}})
	end := time.Now()
	e.EndTime = &end
	e.Status = mcp.ToolExecutionStatusCompleted
	if err := db.SaveToolExecution(e); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := db.QueryRow(`SELECT tool_schema_hash FROM experience_learning_events WHERE id = 'started'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != original {
		t.Fatal("in-flight execution acquired a different tool definition")
	}
}
func TestExperiencePendingEventsSurviveDatabaseRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	enableMemoryLearning(db)
	now := time.Now()
	saveMemoryExecution(t, db, "bad", "u1", "c1", mcp.ToolExecutionStatusFailed, "unknown flag --old", map[string]interface{}{"args": "--old"}, now)
	saveMemoryExecution(t, db, "fixed", "u1", "c1", mcp.ToolExecutionStatusCompleted, "", map[string]interface{}{"args": "--new"}, now.Add(2*time.Second))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.ProcessExperienceEvents(context.Background(), 25); err != nil {
		t.Fatal(err)
	}
	entries, err := db.ListExperiences(ExperienceAccess{UserID: "u1"}, "", "", "", 50, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("restart lost pending events: %v, %v", entries, err)
	}
}
