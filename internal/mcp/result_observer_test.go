package mcp

import (
	"context"
	"cyberstrike-ai/internal/tooloutput"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecutionObserverRunsBeforeTerminalPersistenceAndWait(t *testing.T) {
	server := NewServer(zap.NewNop())
	seen := make(chan struct{}, 1)
	server.SetExecutionObserver(func(ctx context.Context, e *ToolExecution) {
		if e.EndTime == nil {
			return
		}
		if e.Status != "completed" {
			t.Error(e.Status)
		}
		seen <- struct{}{}
	})
	server.RegisterTool(Tool{Name: "fixture"}, func(context.Context, map[string]interface{}) (*ToolResult, error) {
		return &ToolResult{Content: []Content{{Type: "text", Text: "actual"}}}, nil
	})
	result, _, err := server.CallTool(context.Background(), "fixture", nil)
	if err != nil || result == nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	default:
		t.Fatal("tool result returned before observer")
	}
}
func TestNativeResultNoticeNeverOverwritesOriginal(t *testing.T) {
	opts := tooloutput.SpillOpts{RootDir: t.TempDir(), ConversationID: "conversation", ExecutionID: "execution"}
	raw := strings.Repeat("actual original 中文\n", 10000)
	path, err := tooloutput.WriteTruncFile(opts, raw)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("prefix", 1000) + tooloutput.FormatPersistedFromFile(path, len(raw), 1200)
	normalized := NormalizeToolResultForStorageWithSpill(&ToolResult{Content: []Content{{Type: "text", Text: text}}}, 1200, ToolResultSpillConfig{RootDir: opts.RootDir, ConversationID: opts.ConversationID, ExecutionID: opts.ExecutionID})
	if len(ToolResultPlainText(normalized)) > 1200 {
		t.Fatal("unbounded notice")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil || string(data) != raw {
		t.Fatal("original was replaced by its own preview", err)
	}
}
func TestObserverPanicCannotLoseToolResult(t *testing.T) {
	server := NewServer(zap.NewNop())
	server.SetExecutionObserver(func(context.Context, *ToolExecution) { panic("observer") })
	server.RegisterTool(Tool{Name: "fixture"}, func(context.Context, map[string]interface{}) (*ToolResult, error) {
		return &ToolResult{Content: []Content{{Type: "text", Text: "actual"}}}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, _, err := server.CallTool(ctx, "fixture", nil)
	if err != nil || result == nil {
		t.Fatal("observer changed execution", err)
	}
}
