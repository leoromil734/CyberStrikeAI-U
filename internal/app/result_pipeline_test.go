package app

import (
	"context"
	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"encoding/json"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResultPipelinePendingOriginalInventoryAndInactiveAssets(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "pipeline.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.CreateRBACUser("pipeline-user", "Pipeline", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	project, err := db.CreateProject(&database.Project{Name: "pipeline"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SetResourceOwner("project", project.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("pipeline", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SetConversationProjectID(conv.ID, project.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.SetResourceOwner("conversation", conv.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	_, err = db.BeginAssessmentRun(conv.ID, project.ID, "", "", database.AssessmentModeComprehensive, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeOwn, map[string]bool{"project:read": true, "project:write": true, "asset:read": true, "asset:write": true, "monitor:read": true, "monitor:write": true}))
	ctx = mcp.WithMCPConversationID(ctx, conv.ID)
	finished := time.Now().Add(time.Second)
	original := &mcp.ToolExecution{ID: uuid.NewString(), ToolName: "httpx", OwnerUserID: user.ID, ConversationID: conv.ID, Status: "completed", StartTime: time.Now(), EndTime: &finished, Arguments: map[string]interface{}{"json_output": true}, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: `{"url":"https://example.invalid:8443/api?route=account&format=json","host":"192.0.2.1"}` + "\n"}}}}
	if err = db.SaveToolExecution(original); err != nil {
		t.Fatal(err)
	}
	p := &resultPipeline{db: db, root: filepath.Join(t.TempDir(), "reduction"), logger: zap.NewNop(), jobs: make(chan resultJob, 2)}
	p.observe(ctx, original)
	states, err := db.ResultIngestionStates(project.ID, conv.ID, "run-test")
	if err != nil || len(states) != 1 || states[0].State != "pending" {
		t.Fatalf("pending marker not synchronous: %+v %v", states, err)
	}
	p.process(<-p.jobs)
	states, err = db.ResultIngestionStates(project.ID, conv.ID, "run-test")
	if err != nil || len(states) != 1 || states[0].State != "complete" {
		t.Fatalf("processing failed: %+v %v", states, err)
	}
	accessCtx := evidence.WithAccess(ctx, evidence.Access{ProjectID: project.ID, ConversationID: conv.ID, Owner: user.ID})
	artifacts, err := db.ResultArtifacts(accessCtx, original.ID, 10, 0)
	if err != nil || len(artifacts) != 2 {
		t.Fatalf("originals: %+v %v", artifacts, err)
	}
	records, err := db.ReconInventory(accessCtx, original.ID, "endpoint", 10, 0)
	if err != nil || len(records) != 1 || !records[0].CandidateOnly || records[0].ScopeState != "unknown" || !strings.Contains(records[0].RawURL, "route=account&format=json") {
		t.Fatalf("route/authorization was changed: %+v %v", records, err)
	}
	assets, total, err := db.ListAssets(100, 0, database.AssetListFilter{ProjectID: project.ID}, database.RBACListAccess{UserID: user.ID, Scope: database.RBACScopeOwn})
	if err != nil || total < 2 {
		t.Fatalf("assets not projected: %d %v", total, err)
	}
	for _, asset := range assets {
		if asset.Status != "inactive" {
			t.Fatal("unknown scope discovery activated asset")
		}
	}
	var findings int
	if err = db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities`).Scan(&findings); err != nil || findings != 0 {
		t.Fatal("inventory promoted to formal finding")
	}
	_, execution, err := p.authorizedExecution(ctx, original.ID)
	if err != nil || execution.ID != original.ID {
		t.Fatal("own execution inaccessible", err)
	}
	other := authctx.WithPrincipal(ctx, authctx.NewPrincipal("other", "other", database.RBACScopeAll, map[string]bool{"monitor:read": true}))
	if _, _, err := p.authorizedExecution(other, original.ID); err == nil {
		t.Fatal("strict artifact ownership bypassed by global scope")
	}
}

func TestTrustedParserComesFromDirectCommandNotPreview(t *testing.T) {
	tests := map[string]string{"httpx-pd -u https://example.invalid -json": "httpx", "subfinder -d example.invalid": "subfinder", "echo httpx": "", "python3 fake.py": "", "httpx -u example.invalid; id": "", "httpx -u example.invalid | tee x": "", "httpx -u $(echo example.invalid)": ""}
	for command, want := range tests {
		if got := trustedDirectScanner(map[string]interface{}{"command": command}); got != want {
			t.Fatalf("%q => %q want %q", command, got, want)
		}
	}
	if got := resultFormat("nmap", map[string]interface{}{"command": "nmap -oX - 192.0.2.1"}); got != "xml" {
		t.Fatal(got)
	}
	var schema map[string]interface{}
	data, _ := json.Marshal(ledgerStructuredBodySchema())
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
}
