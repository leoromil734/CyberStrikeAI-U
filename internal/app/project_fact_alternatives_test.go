package app

import (
	"encoding/json"
	"strings"
	"testing"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/mcp/builtin"
)

func TestProjectFactBlockedSourceAlternativesAreVisibleAndActionable(t *testing.T) {
	db, server, ctx, projectID := newProjectFactToolTest(t)
	foundSchema := false
	for _, tool := range server.GetAllTools() {
		if tool.Name != builtin.ToolUpsertProjectFact {
			continue
		}
		properties := tool.InputSchema["properties"].(map[string]interface{})
		body := properties["body_fields"].(map[string]interface{})
		_, foundSchema = body["properties"].(map[string]interface{})["alt_tried"]
		if !strings.Contains(tool.Description, "alt_tried") {
			t.Fatal("description omitted blocked-source requirement")
		}
	}
	if !foundSchema {
		t.Fatal("registered tool schema omitted alt_tried")
	}
	key := "recon/source/run-a/oneforall/example"
	fields := map[string]interface{}{"status": "blocked", "tool": "oneforall", "target": "example.test", "raw": 0, "unique": 0, "incremental": 0, "error": "unsupported original format", "evidence": "execution:original"}
	args := map[string]interface{}{"fact_key": key, "summary": "OneForAll original retained, parse unavailable", "body_fields": fields}
	result, _, err := server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("missing alternatives accepted: %v %+v", err, result)
	}
	var diagnostic map[string]interface{}
	if err := json.Unmarshal([]byte(toolResultText(result)), &diagnostic); err != nil {
		t.Fatal(err)
	}
	repairFields, _ := diagnostic["fields"].([]interface{})
	if len(repairFields) != 1 || repairFields[0] != "body_fields.alt_tried" || diagnostic["save_performed"] != false {
		t.Fatalf("repair did not identify exact field: %+v", diagnostic)
	}
	if _, err := db.GetProjectFactByKey(projectID, key); err == nil {
		t.Fatal("rejected write persisted")
	}
	for _, alternative := range []interface{}{
		"subfinder returned 2 hosts; execution:alternative",
		[]interface{}{"subfinder returned 2 hosts; execution:alternative"},
	} {
		fields["alt_tried"] = alternative
		result, _, err = server.CallTool(ctx, builtin.ToolUpsertProjectFact, args)
		if err != nil || result == nil || result.IsError {
			t.Fatalf("documented field could not repair blocked source: %v %s", err, toolResultText(result))
		}
		stored, err := db.GetProjectFactByKey(projectID, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := coverage.ParseLedgerBody(stored.Body)
		if err != nil || parsed["status"] != "blocked" || parsed["alt_tried"] == nil || parsed["evidence"] != "execution:original" {
			t.Fatalf("repair changed evidence or upgraded completion: %v %+v", err, parsed)
		}
	}
}
