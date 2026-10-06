package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"go.uber.org/zap"
)

func newWorkflowSecurityDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "workflow-security.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestWorkflowCreateDoesNotOverwriteExistingDefinition(t *testing.T) {
	db := newWorkflowSecurityDB(t)
	original := &WorkflowDefinition{ID: "protected-workflow", Name: "Original", Version: 7, GraphJSON: `{"original":true}`, Enabled: true}
	if err := db.CreateWorkflowDefinition(original); err != nil {
		t.Fatal(err)
	}
	before, err := db.GetWorkflowDefinition(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacement := &WorkflowDefinition{ID: original.ID, Name: "Replacement", Version: 99, GraphJSON: `{"replacement":true}`}
	if err := db.CreateWorkflowDefinition(replacement); !errors.Is(err, ErrWorkflowAlreadyExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	after, err := db.GetWorkflowDefinition(original.ID)
	if err != nil || after == nil {
		t.Fatalf("read after duplicate: %v", err)
	}
	if after.Name != before.Name || after.GraphJSON != before.GraphJSON || after.Version != before.Version || after.Enabled != before.Enabled || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("duplicate creation modified the existing definition")
	}
	if err := db.UpsertWorkflowDefinition(replacement); err != nil {
		t.Fatalf("explicit update remains available: %v", err)
	}
	after, err = db.GetWorkflowDefinition(original.ID)
	if err != nil || after.Name != "Replacement" {
		t.Fatal("explicit update was not preserved")
	}
}

func TestWorkflowConcurrentCreateHasOneWinner(t *testing.T) {
	db := newWorkflowSecurityDB(t)
	const attempts = 8
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- db.CreateWorkflowDefinition(&WorkflowDefinition{ID: "shared-workflow", Name: fmt.Sprintf("candidate-%d", i), Enabled: true})
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrWorkflowAlreadyExists) {
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successful creates, want 1", successes)
	}
}
