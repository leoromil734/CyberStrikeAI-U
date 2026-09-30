package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func newProjectFactToolTest(t *testing.T) (*database.DB, *mcp.Server, context.Context, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "project-fact-tools.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	proj, err := db.CreateProject(&database.Project{Name: "fact-tools"})
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := db.CreateConversation("fact-tools", database.ConversationCreateMeta{ProjectID: proj.ID})
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(zap.NewNop())
	registerProjectFactTools(server, db, &config.Config{Project: config.ProjectConfig{Enabled: true}}, zap.NewNop())
	ctx := mcp.WithMCPConversationID(context.Background(), conversation.ID)
	return db, server, ctx, proj.ID
}

func TestProjectFactToolUpsertPatch(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	for _, tc := range []struct {
		name       string
		args       map[string]interface{}
		body       string
		category   string
		confidence string
		pinned     bool
		related    string
	}{
		{name: "summary-only", body: "details", category: "recon", confidence: "confirmed", pinned: true, related: "vuln-1"},
		{name: "empty-text-fields", args: map[string]interface{}{"body": "", "category": "", "confidence": ""}, body: "details", category: "recon", confidence: "confirmed", pinned: true, related: "vuln-1"},
		{name: "explicit-unpin", args: map[string]interface{}{"pinned": false}, body: "details", category: "recon", confidence: "confirmed", related: "vuln-1"},
		{name: "explicit-clear-related", args: map[string]interface{}{"related_vulnerability_id": ""}, body: "details", category: "recon", confidence: "confirmed", pinned: true},
		{name: "explicit-clear-both", args: map[string]interface{}{"pinned": false, "related_vulnerability_id": ""}, body: "details", category: "recon", confidence: "confirmed"},
		{name: "replace-fields", args: map[string]interface{}{"body": "new details", "category": "note", "confidence": "deprecated", "pinned": true, "related_vulnerability_id": "vuln-2"}, body: "new details", category: "note", confidence: "deprecated", pinned: true, related: "vuln-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "note/" + tc.name
			original, err := db.UpsertProjectFact(&database.ProjectFact{
				ProjectID: projectID, FactKey: key, Summary: "before", Body: "details",
				Category: "recon", Confidence: "confirmed", Pinned: true, RelatedVulnerabilityID: "vuln-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			args := map[string]interface{}{"fact_key": key, "summary": "after"}
			for k, v := range tc.args {
				args[k] = v
			}
			result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
			if err != nil || result == nil || result.IsError {
				t.Fatalf("upsert result=%#v err=%v text=%q", result, err, toolResultText(result))
			}
			stored, err := db.GetProjectFactByKey(projectID, key)
			if err != nil {
				t.Fatal(err)
			}
			if stored.ID != original.ID || stored.Summary != "after" || stored.Body != tc.body ||
				stored.Category != tc.category || stored.Confidence != tc.confidence || stored.Pinned != tc.pinned ||
				stored.RelatedVulnerabilityID != tc.related {
				t.Fatalf("unexpected patched fact: %#v", stored)
			}
		})
	}
}

func TestProjectFactToolCanonicalEndpointKey(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	inputKey := "recon/endpoint/run-a/guess"
	body := "assessment_id: run-a\nendpoint_url: https://api.example.com:8443/A/b\nmethod: GET\nhost: api.example.com\npath: /A/b\nruntime_status: baselined\nevidence: execution:baseline"
	canonical, err := coverage.CanonicalEndpointFactKey(inputKey, body)
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
		"fact_key": inputKey, "summary": "endpoint baseline", "body": body,
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("upsert: %v %#v", err, result)
	}
	if !strings.Contains(toolResultText(result), canonical) {
		t.Fatal("canonical key missing from tool response")
	}
	if _, err := db.GetProjectFactByKey(projectID, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetProjectFactByKey(projectID, inputKey); err == nil {
		t.Fatal("unsafe alias was also stored")
	}
}

func TestProjectFactToolUpsertCreationDefaults(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{
		"fact_key": "note/defaults", "summary": "created",
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("upsert result=%#v err=%v text=%q", result, err, toolResultText(result))
	}
	stored, err := db.GetProjectFactByKey(projectID, "note/defaults")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Category != "note" || stored.Confidence != "tentative" || stored.Pinned || stored.RelatedVulnerabilityID != "" {
		t.Fatalf("unexpected creation defaults: %#v", stored)
	}
}
