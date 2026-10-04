package agentfinalizer

import (
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func TestPendingToolsOutsideLatestSegmentBlockEvenEmptyExit(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "pending.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("pending", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateConversation("other", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "prior-segment", ConversationID: conv.ID, ToolName: "katana", Status: "running", StartTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"", "已提交报告。"} {
		d := Decide(db, Input{ConversationID: conv.ID, Response: text, ReportSubmitted: true})
		if d.Finalizable || d.CompletionReason != ReasonPendingTools || len(d.PendingExecutionIDs) != 1 || d.PendingExecutionIDs[0] != "prior-segment" {
			t.Fatalf("detached tool disappeared at exit: %+v", d)
		}
	}
	if d := Decide(db, Input{ConversationID: other.ID, Response: "简短答复。"}); !d.Finalizable {
		t.Fatalf("another conversation's tools blocked this answer: %+v", d)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if d := Decide(db, Input{ConversationID: conv.ID, Response: "完整报告。", ReportSubmitted: true}); d.Finalizable || d.CompletionReason != ReasonPendingTools {
		t.Fatalf("database error became success: %+v", d)
	}
}
