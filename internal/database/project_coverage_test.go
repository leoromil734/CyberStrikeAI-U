package database

import (
	"go.uber.org/zap"
	"path/filepath"
	"testing"
)

func TestListProjectCoverageFactsIsScopedAndSkipsUnrelatedBodies(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "coverage-query.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	project, err := db.CreateProject(&Project{Name: "coverage-query"})
	if err != nil {
		t.Fatal(err)
	}
	one, err := db.CreateConversation("one", ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	two, err := db.CreateConversation("two", ConversationCreateMeta{ProjectID: project.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range []ProjectFact{
		{FactKey: "recon/phase/own", SourceConversationID: one.ID},
		{FactKey: "recon/phase/other", SourceConversationID: two.ID},
		{FactKey: "recon/phase/deprecated", SourceConversationID: one.ID, Confidence: "deprecated"},
		{FactKey: "finding/unrelated", SourceConversationID: one.ID, Body: "unrelated POC body"},
	} {
		fact.ProjectID, fact.Summary = project.ID, "fixture"
		if _, err := db.UpsertProjectFact(&fact); err != nil {
			t.Fatal(err)
		}
	}
	facts, err := db.ListProjectCoverageFacts(project.ID, one.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].FactKey != "recon/phase/own" {
		t.Fatalf("coverage query leaked unrelated facts: %+v", facts)
	}
}
