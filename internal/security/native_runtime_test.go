package security

import (
	"context"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"errors"
	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/google/uuid"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeRuntimeBoundsModelOutputAndPreservesFullOriginal(t *testing.T) {
	id := uuid.NewString()
	base := t.TempDir()
	ctx := mcp.WithMCPExecutionID(context.Background(), id)
	ctx = mcp.WithMCPConversationID(ctx, "c1")
	acquired, released := false, false
	ctx = mcp.WithLocalExecutionRuntime(ctx, mcp.LocalExecutionRuntime{SpillRoot: base, MaxOutputBytes: 1200, Activity: make(chan struct{}, 1), Acquire: func(context.Context, string, map[string]interface{}) (func(), error) {
		acquired = true
		return func() { released = true }, nil
	}})
	sr, err := NewEinoStreamingShell().ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: "i=0; while [ $i -lt 4000 ]; do printf 'actual-original-line\\n'; i=$((i+1)); done"})
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	var model strings.Builder
	for {
		response, err := sr.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if response != nil {
			model.WriteString(response.Output)
		}
	}
	if !acquired || !released || model.Len() > 1200 || !strings.Contains(model.String(), "persisted-output") {
		t.Fatalf("runtime not bounded/shared: len=%d acquire=%v release=%v", model.Len(), acquired, released)
	}
	root, err := evidence.ReductionRoot(base, evidence.Execution{ID: id, Access: evidence.Access{ConversationID: "c1"}})
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root.Path, id))
	if err != nil || strings.Count(string(original), "actual-original-line") != 4000 {
		t.Fatal("full original lost", err)
	}
}
