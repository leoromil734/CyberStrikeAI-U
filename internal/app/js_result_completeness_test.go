package app

import (
	"context"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"testing"
)

func TestJSManifestCanOnlyDowngradeCompleteness(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "js-metadata.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, test := range []struct {
		body     string
		initial  string
		want     string
		timedOut bool
	}{
		{`{"complete":true,"scan_complete":true,"export_complete":true,"raw_complete":true}`, evidence.Complete, evidence.Complete, false},
		{`{"complete":true,"scan_complete":true,"export_complete":true,"raw_complete":true}`, evidence.Partial, evidence.Partial, false},
		{`{"complete":true,"scan_complete":false,"export_complete":true,"raw_complete":true}`, evidence.Complete, evidence.Partial, false},
		{`{"complete":false,"partial":true,"timed_out":true}`, evidence.Complete, evidence.Partial, true},
		{`not json`, evidence.Complete, evidence.Partial, false},
	} {
		e := evidence.Execution{ID: uuid.NewString(), Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "u"}, Tool: "jsapiscan", Status: "completed", Completion: test.initial}
		ctx := evidence.WithAccess(context.Background(), e.Access)
		if err = db.RecordExecution(ctx, e); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "execution-"+e.ID)
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(test.body), 0600); err != nil {
			t.Fatal(err)
		}
		roots := []evidence.ManagedRoot{{Path: dir, Access: e.Access, ExecutionID: e.ID}}
		registry, err := evidence.NewRegistry(db, roots, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := (&resultPipeline{db: db}).jsExecutionCompleteness(ctx, e, registry, roots)
		registry.Close()
		if got.Completion != test.want || got.TimedOut != test.timedOut {
			t.Fatalf("manifest improperly promoted completion: %+v", got)
		}
	}
}
