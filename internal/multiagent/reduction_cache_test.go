package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/workspaceguard"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/cloudwego/eino/adk/middlewares/reduction"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func reductionTestNotice(path string) string {
	return "<persisted-output>工具结果已保存至: " + path + "\n使用 read_file 进行查看</persisted-output>"
}

func TestReductionCacheReplayPreservesOriginal(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	local, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.MultiAgentEinoMiddlewareConfig{ReductionRootDir: base, ReductionMaxTokensForClear: 1}
	middleware, err := buildReductionMiddleware(ctx, cfg, "", "cache-test", local, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := strings.Repeat("actual execution evidence\n", 80)
	call := func(id string) *schema.Message {
		return schema.AssistantMessage("", []schema.ToolCall{{ID: id, Type: "function", Function: schema.FunctionCall{Name: "exec", Arguments: `{}`}}})
	}
	state := &adk.ChatModelAgentState{Messages: []adk.Message{
		schema.UserMessage("current assessment"), call("old-call"), schema.ToolMessage(original, "old-call", schema.WithToolName("exec")),
		call("recent-call"), schema.ToolMessage("recent result", "recent-call", schema.WithToolName("exec")),
	}}
	_, state, err = middleware.BeforeModelRewriteState(ctx, state, &adk.ModelContext{})
	if err != nil {
		t.Fatal(err)
	}
	path := reductionReference(state.Messages[2].Content)
	if path == "" || state.Messages[1].Extra[agent.ReductionClearedTraceKey] != true {
		t.Fatalf("fixture was not cleared with a replay marker: %+v", state.Messages)
	}
	assertOriginal := func() {
		t.Helper()
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != original {
			t.Fatalf("clear notice overwrote the original: %v %q", readErr, got)
		}
		files, globErr := filepath.Glob(filepath.Join(filepath.Dir(path), "*"))
		if globErr != nil || len(files) != 1 {
			t.Fatalf("replay generated a growing reference chain: %v %v", files, globErr)
		}
	}
	assertOriginal()
	encoded, err := json.Marshal(state.Messages)
	if err != nil {
		t.Fatal(err)
	}
	history, err := agent.ParseTraceMessages(string(encoded))
	if err != nil || !history[1].ReductionCleared {
		t.Fatalf("trace bridge lost reduction state: %+v %v", history, err)
	}
	state.Messages = historyToMessages(history, nil, &cfg)
	if state.Messages[1].Extra[agent.ReductionClearedTraceKey] != true {
		t.Fatal("restored Eino message lost clear-once metadata")
	}
	_, state, err = middleware.BeforeModelRewriteState(ctx, state, &adk.ModelContext{})
	if err != nil {
		t.Fatal(err)
	}
	assertOriginal()
	// Old traces have already lost Extra. Backend idempotence must protect
	// their surviving original too, not merely future metadata-aware traces.
	for i := 0; i < 3; i++ {
		state.Messages[1].Extra = nil
		_, state, err = middleware.BeforeModelRewriteState(ctx, state, &adk.ModelContext{})
		if err != nil {
			t.Fatal(err)
		}
		if reductionReference(state.Messages[2].Content) != path {
			t.Fatal("legacy replay stopped referring to the actual original")
		}
		assertOriginal()
	}
}

func TestReductionCacheTruncationAndClearShareOriginal(t *testing.T) {
	ctx := context.Background()
	backend, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.MultiAgentEinoMiddlewareConfig{ReductionRootDir: t.TempDir(), ReductionMaxTokensForClear: 1, ReductionMaxLengthForTrunc: 64}
	mw, err := buildReductionMiddleware(ctx, cfg, "", "trunc-clear", backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := strings.Repeat("complete original with tail evidence\n", 30)
	endpoint, err := mw.WrapInvokableToolCall(ctx, func(context.Context, string, ...tool.Option) (string, error) { return original, nil }, &adk.ToolContext{Name: "exec", CallID: "call"})
	if err != nil {
		t.Fatal(err)
	}
	notice, err := endpoint(ctx, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	path := reductionReference(notice)
	if path == "" || filepath.Base(filepath.Dir(path)) != "trunc" {
		t.Fatalf("no truncation reference: %q", notice)
	}
	state := &adk.ChatModelAgentState{Messages: []adk.Message{
		schema.AssistantMessage("", []schema.ToolCall{{ID: "call", Type: "function", Function: schema.FunctionCall{Name: "exec", Arguments: `{}`}}}),
		schema.ToolMessage(notice, "call", schema.WithToolName("exec")),
		schema.AssistantMessage("", []schema.ToolCall{{ID: "latest", Type: "function", Function: schema.FunctionCall{Name: "exec", Arguments: `{}`}}}),
		schema.ToolMessage("latest result", "latest", schema.WithToolName("exec")),
	}}
	_, state, err = mw.BeforeModelRewriteState(ctx, state, &adk.ModelContext{})
	if err != nil || reductionReference(state.Messages[1].Content) != path {
		t.Fatalf("clear wrapped rather than reused truncation reference: %v %+v", err, state)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != original {
		t.Fatalf("truncated original lost on clear: %v", err)
	}
	if files, _ := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(path)), "clear", "*")); len(files) != 0 {
		t.Fatalf("created a clear pointer chain: %v", files)
	}
	// A later genuine execution may reuse a model-generated call ID. Its bytes
	// must get a fresh path rather than silently reuse/overwrite an old result.
	second, err := endpoint(ctx, `{}`)
	if err != nil || reductionReference(second) == path {
		t.Fatalf("reused call ID collides at truncation: %v %s", err, second)
	}
}

func TestReductionCacheWritesAreImmutable(t *testing.T) {
	ctx := context.Background()
	backend := &reductionCacheBackend{root: t.TempDir(), conversationID: "one"}
	path := filepath.Join(backend.root, "clear", "original")
	original := "actual result"
	write := func(content string) error {
		return backend.Write(ctx, &filesystem.WriteRequest{FilePath: path, Content: content})
	}
	if err := write(original); err != nil {
		t.Fatal(err)
	}
	if err := write(original); err != nil {
		t.Fatal("identical retry must be idempotent:", err)
	}
	for _, notice := range []string{
		reductionTestNotice(path),
		"<persisted-output>Tool result saved to: " + path + "\nUse read_file to view</persisted-output>",
		"<persisted-output>\nOutput too large (999). Full output saved to: " + path + "\nPreview (first 4):\ndata\n</persisted-output>",
		"<persisted-output>\n输出结果过大 (999). 完整输出保存到: " + path + "\n预览:\ndata\n</persisted-output>",
	} {
		if err := write(notice); err != nil {
			t.Fatal(err)
		}
	}
	if err := write("different execution"); err == nil {
		t.Fatal("conflicting original overwrite accepted")
	}
	got, _ := os.ReadFile(path)
	if string(got) != original {
		t.Fatalf("original changed: %q", got)
	}
	missing := filepath.Join(backend.root, "clear", "missing")
	if err := backend.Write(ctx, &filesystem.WriteRequest{FilePath: missing, Content: reductionTestNotice(missing)}); err == nil {
		t.Fatal("created a self-referential original")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("self-reference failure left a file")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := backend.Write(ctx, &filesystem.WriteRequest{FilePath: outside, Content: "private"}); err == nil {
		t.Fatal("write escaped reduction root")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := backend.Write(cancelled, &filesystem.WriteRequest{FilePath: path, Content: original}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write not stopped: %v", err)
	}
}

func TestReductionCacheReusedCallIDsNeverCollide(t *testing.T) {
	ctx := context.Background()
	backend := &reductionCacheBackend{root: t.TempDir(), conversationID: "one"}
	type result struct {
		path string
		err  error
	}
	results := make(chan result, 32)
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			path, err := backend.offloadPath("clear")(ctx, &reduction.ToolDetail{ToolContext: &adk.ToolContext{CallID: "../../reused-call"}})
			if err == nil {
				err = backend.Write(ctx, &filesystem.WriteRequest{FilePath: path, Content: "original"})
			}
			results <- result{path, err}
		}()
	}
	workers.Wait()
	close(results)
	seen := map[string]bool{}
	for result := range results {
		if result.err != nil || !workspaceguard.Within(backend.root, result.path) || seen[result.path] {
			t.Fatalf("unsafe/colliding reused ID: %+v", result)
		}
		seen[result.path] = true
	}
}

func TestReductionReferenceDoesNotFollowForeignOrEmbeddedPaths(t *testing.T) {
	ctx := context.Background()
	backend := &reductionCacheBackend{root: t.TempDir(), conversationID: "one"}
	foreign := filepath.Join(t.TempDir(), "secret")
	for _, text := range []string{reductionTestNotice(foreign), "quoted example: " + reductionTestNotice(foreign)} {
		detail := &reduction.ToolDetail{ToolResult: &schema.ToolResult{Parts: []schema.ToolOutputPart{{Type: schema.ToolPartTypeText, Text: text}}}}
		path, err := backend.offloadPath("clear")(ctx, detail)
		if err != nil || path == foreign || !workspaceguard.Within(backend.root, path) {
			t.Fatalf("foreign reference used as an output location: %s %v", path, err)
		}
	}
	missing := filepath.Join(backend.root, "clear", "missing")
	detail := &reduction.ToolDetail{ToolResult: &schema.ToolResult{Parts: []schema.ToolOutputPart{{Type: schema.ToolPartTypeText, Text: reductionTestNotice(missing)}}}}
	if _, err := backend.offloadPath("clear")(ctx, detail); err == nil {
		t.Fatal("missing original was presented as a valid offload")
	}
}

func TestReductionCacheRejectsSymlinks(t *testing.T) {
	backend := &reductionCacheBackend{root: t.TempDir()}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(backend.root, "clear")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := backend.Write(context.Background(), &filesystem.WriteRequest{FilePath: filepath.Join(backend.root, "clear", "original"), Content: "secret"}); err == nil {
		t.Fatal("symlink reduction directory accepted")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("outside directory was modified")
	}
}

func TestHistoricalSelfReferenceReadFailsWithoutRewritingCache(t *testing.T) {
	workspace, evidence := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(evidence, "clear"), 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(evidence, "clear", "historical")
	body := reductionTestNotice(path)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	policy := &workspaceguard.Policy{Workspace: workspace, EvidenceRoot: evidence, ReadOnlyRoots: []string{evidence}}
	ctx := workspaceguard.WithPolicy(context.Background(), policy)
	reader := newWorkspaceFilesystem(ctx)
	if _, err := reader.Read(ctx, &filesystem.ReadRequest{FilePath: path}); err == nil || !strings.Contains(err.Error(), "自引用") || !strings.Contains(err.Error(), "query_result_artifacts") {
		t.Fatalf("historical circular notice was returned as usable evidence: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != body {
		t.Fatal("historical cache was silently rewritten")
	}
	// Ordinary workspace documents are not cache metadata, even if their text
	// happens to show a self-reference as an example.
	doc := filepath.Join(workspace, "example.txt")
	if err := os.WriteFile(doc, []byte(reductionTestNotice(doc)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(ctx, &filesystem.ReadRequest{FilePath: doc}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("line one\nline two\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := reader.Read(ctx, &filesystem.ReadRequest{FilePath: path, Offset: 2, Limit: 1})
	if err != nil || out.Content != "line two" {
		t.Fatalf("inspection moved the line-read cursor: %+v %v", out, err)
	}
}
