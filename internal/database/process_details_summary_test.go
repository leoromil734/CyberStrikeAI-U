package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestProcessDetailsSummaryPairsMixedIdentifiedAndIDLessResults(t *testing.T) {
	db, conversationID, messageID := setupProcessDetailsSummaryTest(t)
	for _, id := range []string{"call-1", "call-2", "call-3", "call-4"} {
		if err := addSummaryDetailInOrder(db, messageID, conversationID, "tool_call", "call", map[string]interface{}{
			"toolName": "http-framework-test", "toolCallId": id,
		}); err != nil {
			t.Fatalf("AddProcessDetail(tool_call): %v", err)
		}
	}
	results := []map[string]interface{}{
		{"toolName": "http-framework-test", "toolCallId": "call-1", "success": true},
		{"toolName": "http-framework-test", "toolCallId": "call-2", "success": true},
		{"toolName": "http-framework-test", "success": true},
		{"toolName": "http-framework-test", "success": true},
	}
	for _, result := range results {
		if err := addSummaryDetailInOrder(db, messageID, conversationID, "tool_result", "result", result); err != nil {
			t.Fatalf("AddProcessDetail(tool_result): %v", err)
		}
	}

	summary, err := db.GetProcessDetailsSummary(messageID)
	if err != nil {
		t.Fatalf("GetProcessDetailsSummary: %v", err)
	}
	if len(summary.ToolExecutions) != 4 {
		t.Fatalf("tool executions = %d, want 4", len(summary.ToolExecutions))
	}
	for i, execution := range summary.ToolExecutions {
		if execution.Status != "completed" {
			details, _ := db.GetProcessDetails(messageID)
			t.Fatalf("execution %d status = %q, want completed; ordered details=%+v", i, execution.Status, details)
		}
	}
}

func TestProcessDetailsSummaryPairsRepeatedToolCallIDsFIFO(t *testing.T) {
	db, conversationID, messageID := setupProcessDetailsSummaryTest(t)
	for i := 0; i < 2; i++ {
		if err := addSummaryDetailInOrder(db, messageID, conversationID, "tool_call", "call", map[string]interface{}{
			"toolName": "execute", "toolCallId": "legacy-reused-id",
		}); err != nil {
			t.Fatalf("AddProcessDetail(tool_call): %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := addSummaryDetailInOrder(db, messageID, conversationID, "tool_result", "result", map[string]interface{}{
			"toolName": "execute", "toolCallId": "legacy-reused-id", "success": true,
		}); err != nil {
			t.Fatalf("AddProcessDetail(tool_result): %v", err)
		}
	}

	summary, err := db.GetProcessDetailsSummary(messageID)
	if err != nil {
		t.Fatalf("GetProcessDetailsSummary: %v", err)
	}
	if len(summary.ToolExecutions) != 2 {
		t.Fatalf("tool executions = %d, want 2", len(summary.ToolExecutions))
	}
	for i, execution := range summary.ToolExecutions {
		if execution.Status != "completed" {
			details, _ := db.GetProcessDetails(messageID)
			t.Fatalf("execution %d status = %q, want completed; ordered details=%+v", i, execution.Status, details)
		}
	}
}

func TestProcessDetailsSummaryDoesNotReportPersistedOrphanAsRunning(t *testing.T) {
	db, conversationID, messageID := setupProcessDetailsSummaryTest(t)
	if err := addSummaryDetailInOrder(db, messageID, conversationID, "tool_call", "call", map[string]interface{}{
		"toolName": "execute", "toolCallId": "orphan",
	}); err != nil {
		t.Fatalf("AddProcessDetail(tool_call): %v", err)
	}
	summary, err := db.GetProcessDetailsSummary(messageID)
	if err != nil {
		t.Fatalf("GetProcessDetailsSummary: %v", err)
	}
	if len(summary.ToolExecutions) != 1 || summary.ToolExecutions[0].Status != "result_missing" {
		t.Fatalf("tool executions = %#v, want result_missing", summary.ToolExecutions)
	}
}

// These tests assert FIFO pairing for chronologically ordered events. On
// Windows consecutive time.Now calls can share a wall-clock timestamp, making
// the UUID tie-breaker randomize call/result order. Give the fixture explicit
// timestamps rather than relying on scheduler timing or adding sleeps.
func addSummaryDetailInOrder(db *DB, messageID, conversationID, eventType, message string, data interface{}) error {
	var ordinal int
	if err := db.QueryRow("SELECT COUNT(*) FROM process_details WHERE message_id = ?", messageID).Scan(&ordinal); err != nil {
		return err
	}
	id, err := db.AddProcessDetailWithID(messageID, conversationID, eventType, message, data)
	if err != nil {
		return err
	}
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(ordinal) * time.Second)
	_, err = db.Exec("UPDATE process_details SET created_at = ? WHERE id = ?", createdAt, id)
	return err
}

func setupProcessDetailsSummaryTest(t *testing.T) (*DB, string, string) {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "process-details.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conversation, err := db.CreateConversation("process details", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	message, err := db.AddMessage(conversation.ID, "assistant", "done", nil)
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	return db, conversation.ID, message.ID
}
