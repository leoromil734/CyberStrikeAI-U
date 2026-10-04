package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestReplayResultIngestionsPersistedPreviewRequiresRetainedOriginal(t *testing.T) {
	for _, tool := range []string{"exec", "subfinder"} {
		for _, retained := range []bool{false, true} {
			name := tool + "/missing"
			if retained {
				name = tool + "/retained"
			}
			t.Run(name, func(t *testing.T) {
				db, err := database.NewDB(filepath.Join(t.TempDir(), "spill.db"), zap.NewNop())
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				_, excluded, _ := ingestionReplayFixture(t, db, "excluded-failed", "failed")
				_, pending, _ := ingestionReplayFixture(t, db, "excluded-pending", "pending")
				cfg := &config.Config{}
				cfg.MultiAgent.EinoMiddleware.ReductionRootDir = filepath.Join(t.TempDir(), "reduction")
				start := time.Now().UTC()
				end := start.Add(time.Second)
				e := evidence.Execution{ID: uuid.NewString(), Access: evidence.Access{Owner: "owner", ProjectID: "project", ConversationID: "conversation"}, Tool: tool, Status: "completed", Completion: evidence.Complete, Capped: true, StartedAt: start, FinishedAt: end}
				original := &mcp.ToolExecution{ID: e.ID, OwnerUserID: e.Owner, ConversationID: e.ConversationID, ToolName: tool, Status: e.Status, StartTime: start, EndTime: &end, Arguments: map[string]interface{}{}, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "<persisted-output>preview only</persisted-output>"}}}}
				ctx := evidence.WithAccess(context.Background(), e.Access)
				if err = db.PersistResultIngestion(ctx, e, original, database.ResultIngestionProjection{}); err != nil {
					t.Fatal(err)
				}
				if retained {
					root, err := evidence.ReductionRoot(cfg.MultiAgent.EinoMiddleware.ReductionRootDir, e)
					if err != nil {
						t.Fatal(err)
					}
					if err = writeManagedOriginal(root.Path, e.ID, []byte("www.example.invalid\n")); err != nil {
						t.Fatal(err)
					}
				}
				// Empty means no work, including unrelated pending jobs.
				if reports, err := ReplayResultIngestions(ctx, db, cfg, zap.NewNop(), nil); err != nil || len(reports) != 0 {
					t.Fatalf("empty selection: %+v %v", reports, err)
				}
				before, err := db.ResultIngestionJob(ctx, e.ID)
				if err != nil || before.State != "pending" || before.TotalAttempts != 0 {
					t.Fatalf("empty selection processed a job: %+v %v", before, err)
				}
				// Duplicate IDs must still be processed only once per invocation.
				reports, replayErr := ReplayResultIngestions(ctx, db, cfg, zap.NewNop(), []string{e.ID, e.ID})
				if len(reports) != 1 || reports[0].TotalAttempts != 1 {
					t.Fatalf("selection/attempts: %+v %v", reports, replayErr)
				}
				wantArtifacts := 1
				if retained {
					wantArtifacts = 2
					if replayErr != nil || reports[0].State != "complete" {
						t.Fatalf("retained original not processed: %+v %v", reports, replayErr)
					}
				} else {
					if replayErr == nil || reports[0].State != "partial" || !strings.Contains(reports[0].Reason, "no retained output original") {
						t.Fatalf("input-only preview reported success: %+v %v", reports, replayErr)
					}
					stored, err := db.ResultExecution(ctx, e.ID)
					if err != nil || stored.Completion != evidence.Partial || !stored.Capped {
						t.Fatalf("missing original completeness not saved: %+v %v", stored, err)
					}
					// A second explicitly selected replay must preserve both the
					// partial result and the immutable binding after the downgrade.
					reports, replayErr = ReplayResultIngestions(ctx, db, cfg, zap.NewNop(), []string{e.ID})
					if replayErr == nil || len(reports) != 1 || reports[0].State != "partial" || reports[0].TotalAttempts != 2 || !reports[0].Requeued || !strings.Contains(reports[0].Reason, "no retained output original") {
						t.Fatalf("partial replay drifted: %+v %v", reports, replayErr)
					}
				}
				artifacts, err := db.ResultArtifacts(ctx, e.ID, 10, 0)
				if err != nil || len(artifacts) != wantArtifacts {
					t.Fatalf("missing/duplicate originals: %+v %v", artifacts, err)
				}
				if !retained && artifacts[0].Kind != "input" {
					t.Fatalf("preview substituted for original: %+v", artifacts)
				}
				for _, unselected := range []struct{ id, state string }{{excluded.ID, "failed"}, {pending.ID, "pending"}} {
					job, err := db.ResultIngestionJob(ctx, unselected.id)
					if err != nil || job.State != unselected.state || job.TotalAttempts != 0 {
						t.Fatalf("unselected job touched: %+v %v", job, err)
					}
				}
			})
		}
	}
}
