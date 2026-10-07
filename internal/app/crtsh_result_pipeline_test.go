package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestCRTShExecutionFlowsIntoCandidateInventory(t *testing.T) {
	if resultFormat("crtsh_search", nil) != "json" {
		t.Fatal("crt.sh JSON must not be ingested as text/JSONL")
	}
	db, err := database.NewDB(filepath.Join(t.TempDir(), "crtsh.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.CreateRBACUser("crt-user", "CRT User", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	project, err := db.CreateProject(&database.Project{Name: "crt fixture"})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("crt fixture", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetConversationProjectID(conv.ID, project.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BeginAssessmentRun(conv.ID, project.ID, "", "", database.AssessmentModeComprehensive, "crt-run"); err != nil {
		t.Fatal(err)
	}
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAll, map[string]bool{"project:read": true, "project:write": true, "asset:write": true, "asset:read": true, "monitor:read": true, "monitor:write": true}))
	ctx = mcp.WithMCPConversationID(ctx, conv.ID)
	body := `{"schema":"csai.crtsh.v1","source":"crt.sh","query_domain":"example.test","status":"success","partial":false,"truncated":false,"coverage_complete":false,"candidate_only":true,"verification":"unverified","records":[{"host":"api.example.test","source":"crt.sh","candidate_only":true,"verification":"unverified","certificates":[{"id":"123","url":"https://crt.sh/?id=123","name":"api.example.test","not_before":"2024-01-01","not_after":"2024-12-31"}]}],"counts":{"unique_hosts":1}}`
	end := time.Now().Add(time.Second)
	execution := &mcp.ToolExecution{ID: uuid.NewString(), ToolName: "crtsh_search", OwnerUserID: user.ID, ConversationID: conv.ID, Status: "completed", StartTime: time.Now(), EndTime: &end, Arguments: map[string]interface{}{"domain": "example.test"}, Result: textResult(body, false)}
	if err := db.SaveToolExecution(execution); err != nil {
		t.Fatal(err)
	}
	pipeline := &resultPipeline{db: db, root: filepath.Join(t.TempDir(), "reduction"), logger: zap.NewNop(), wake: make(chan struct{}, 1)}
	pipeline.observe(ctx, execution)
	claim, err := db.ClaimResultIngestion(ctx, execution.ID, resultIngestionLease)
	if err != nil || claim == nil {
		t.Fatalf("claim: %v %v", claim, err)
	}
	if err := pipeline.runClaim(ctx, *claim); err != nil {
		t.Fatal(err)
	}
	access := evidence.WithAccess(ctx, evidence.Access{ProjectID: project.ID, ConversationID: conv.ID, Owner: user.ID})
	records, err := db.ReconInventory(access, execution.ID, "host", 10, 0)
	if err != nil || len(records) != 1 || records[0].Host != "api.example.test" || !records[0].CandidateOnly || records[0].ScopeState != "unknown" {
		t.Fatalf("CT provenance/scope lost: %+v %v", records, err)
	}
	var findings int
	if err := db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&findings); err != nil || findings != 0 {
		t.Fatal("certificate candidate became a finding")
	}
}
