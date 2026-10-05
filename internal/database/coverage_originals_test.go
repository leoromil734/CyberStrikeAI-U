package database

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/evidence"
)

func TestCoverageHTTPExecutionQueryExactPartition(t *testing.T) {
	db := newResultArtifactTestDB(t)
	base := resultTestExecution("valid")
	base.Tool = "exec"
	binding := coverage.OriginalBinding{Access: base.Access, AssessmentID: base.AssessmentID, ScopeID: base.ScopeID}
	for _, name := range []string{"valid", "conversation", "owner", "project", "assessment", "scope", "read-file", "failed", "partial", "capped", "timeout"} {
		e := base
		e.ID = name
		switch name {
		case "conversation":
			e.ConversationID = "other"
		case "owner":
			e.Owner = "other"
		case "project":
			e.ProjectID = "other"
		case "assessment":
			e.AssessmentID = "other"
		case "scope":
			e.ScopeID = "other"
		case "read-file":
			e.Tool = "read_file"
		case "failed":
			e.Status = "failed"
		case "partial":
			e.Completion = evidence.Partial
		case "capped":
			e.Capped = true
		case "timeout":
			e.TimedOut = true
		}
		if err := db.RecordExecution(evidence.WithAccess(context.Background(), e.Access), e); err != nil {
			t.Fatal(err)
		}
	}
	ctx := evidence.WithAccess(context.Background(), base.Access)
	got, err := db.AssessmentHTTPExecutions(ctx, binding)
	if err != nil || len(got) != 1 || got[0].ID != "valid" {
		t.Fatalf("cross-binding/status execution included: %+v %v", got, err)
	}
	binding.Owner = "other"
	if _, err := db.AssessmentHTTPExecutions(ctx, binding); err == nil {
		t.Fatal("context owner mismatch accepted")
	}
}

func TestCoverageOriginalBindingUsesCurrentOwnerAndScope(t *testing.T) {
	db := newResultArtifactTestDB(t)
	for _, statement := range []string{
		`CREATE TABLE projects(id TEXT PRIMARY KEY,scope_json TEXT)`,
		`CREATE TABLE conversations(id TEXT PRIMARY KEY,project_id TEXT,owner_user_id TEXT)`,
		`INSERT INTO projects(id,scope_json) VALUES ('p1','["example.invalid"]')`,
		`INSERT INTO conversations(id,project_id,owner_user_id) VALUES ('c1','p1','u1')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	b, err := db.CoverageOriginalBinding("p1", "c1", "assessment1")
	if err != nil {
		t.Fatal(err)
	}
	if b.Owner != "u1" || b.ScopeID == "" {
		t.Fatalf("missing binding: %+v", b)
	}
	if _, err := db.CoverageOriginalBinding("other", "c1", "assessment1"); err == nil {
		t.Fatal("project rebind accepted")
	}
	if _, err := db.Exec(`UPDATE projects SET scope_json='["different.invalid"]' WHERE id='p1'`); err != nil {
		t.Fatal(err)
	}
	changed, err := db.CoverageOriginalBinding("p1", "c1", "assessment1")
	if err != nil {
		t.Fatal(err)
	}
	if changed.ScopeID == b.ScopeID {
		t.Fatal("scope change reused original binding")
	}
	if _, err := db.Exec(`UPDATE conversations SET owner_user_id='' WHERE id='c1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CoverageOriginalBinding("p1", "c1", "assessment1"); err == nil {
		t.Fatal("owner inferred from old tool rows")
	}
}
