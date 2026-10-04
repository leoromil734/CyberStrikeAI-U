package app

import (
	"context"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
)

func TestProjectFactBudgetRejectsBeforeDatabaseMutation(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	before, err := db.UpsertProjectFact(&database.ProjectFact{ProjectID: projectID, FactKey: "note/budget-fixture", Summary: "original", Body: "original evidence", Confidence: "tentative"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	ctx = mcp.WithAgentRunBudget(ctx, cancel)
	defer mcp.CloseAgentRunBudget(ctx)
	// Trusted fixture snapshots a one-write budget, then exhausts it. The
	// production tool receives its ordinary configured limit and cannot enlarge it.
	if err = mcp.AdmitProjectFactWrite(ctx, 1); err != nil {
		t.Fatal(err)
	}
	_, _, _ = server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": before.FactKey, "summary": "must never be stored"})
	if reason := mcp.AgentRunBudgetStopReason(context.Cause(ctx)); reason != "fact_write_budget_exceeded" {
		t.Fatalf("missing cancellation: %v", context.Cause(ctx))
	}
	stored, err := db.GetProjectFactByKey(projectID, before.FactKey)
	if err != nil || stored.Summary != "original" || stored.Body != "original evidence" {
		t.Fatalf("budget stop changed existing evidence: %+v %v", stored, err)
	}
}

func TestProjectFactToolWarnsAgainstInventoryCopying(t *testing.T) {
	_, server, _, _ := newProjectFactToolTest(t)
	for _, tool := range server.GetAllTools() {
		if tool.Name == builtin.ToolUpsertProjectFact {
			for _, text := range []string{"不要逐行复制成 fact", "禁止为了结项", "未完成范围"} {
				if !strings.Contains(tool.Description, text) {
					t.Fatalf("missing guidance: %s", text)
				}
			}
			return
		}
	}
	t.Fatal("fact tool missing")
}
