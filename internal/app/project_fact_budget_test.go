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
	result, _, callErr := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": before.FactKey, "summary": "must never be stored"})
	if callErr != nil || result == nil || !result.IsError || !strings.Contains(mcp.ToolResultPlainText(result), "事实写入额度") {
		t.Fatalf("fact quota must be a recoverable tool response: %+v %v", result, callErr)
	}
	if ctx.Err() != nil {
		t.Fatalf("fact quota cancelled testing/reporting: %v", context.Cause(ctx))
	}
	stored, err := db.GetProjectFactByKey(projectID, before.FactKey)
	if err != nil || stored.Summary != "original" || stored.Body != "original evidence" {
		t.Fatalf("budget stop changed existing evidence: %+v %v", stored, err)
	}
}

func TestProjectFactInvalidAndNoopWritesDoNotSpendQuota(t *testing.T) {
	_, server, ctx, _ := newProjectFactToolTest(t)
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	ctx = mcp.WithAgentRunBudget(ctx, cancel)
	defer mcp.CloseAgentRunBudget(ctx)
	for i := 0; i < 3; i++ {
		result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": "note/invalid"})
		if err == nil && (result == nil || !result.IsError) {
			t.Fatal("invalid fact unexpectedly accepted")
		}
	}
	// If a rejected field spent the quota, this first trusted admission fails.
	if err := mcp.AdmitProjectFactWrite(ctx, 2); err != nil {
		t.Fatal(err)
	}
	args := map[string]interface{}{"fact_key": "note/same", "summary": "saved once", "body": "local fixture; no request executed"}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
	if err != nil || result == nil || result.IsError {
		t.Fatalf("valid mutation was not admitted: %+v %v", result, err)
	}
	for i := 0; i < 3; i++ {
		result, _, err = server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
		if err != nil || result == nil || result.IsError || !strings.Contains(mcp.ToolResultPlainText(result), "未变化") {
			t.Fatalf("no-op retry was charged/rejected: %+v %v", result, err)
		}
	}
	result, _, err = server.CallTool(ctx, builtin.ToolUpsertProjectFact, map[string]interface{}{"fact_key": "note/same", "summary": "changed"})
	if err != nil || result == nil || !result.IsError || ctx.Err() != nil {
		t.Fatalf("quota did not isolate mutation from run lifetime: %+v %v", result, err)
	}
	result, _, err = server.CallTool(ctx, builtin.ToolGetProjectFact, map[string]interface{}{"fact_key": "note/same"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("read/report preparation was blocked by quota: %+v %v", result, err)
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
