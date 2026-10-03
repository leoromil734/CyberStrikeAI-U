package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/workspaceguard"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func readProgressContext(t *testing.T, mw adk.ChatModelAgentMiddleware, parent context.Context) context.Context {
	t.Helper()
	runCtx := &adk.ChatModelAgentContext{Instruction: "unchanged"}
	ctx, gotRunCtx, err := mw.BeforeAgent(parent, runCtx)
	if err != nil || gotRunCtx != runCtx {
		t.Fatalf("BeforeAgent changed agent settings: runCtx=%p err=%v", gotRunCtx, err)
	}
	return ctx
}

func wrapProgressRead(t *testing.T, mw adk.ChatModelAgentMiddleware, name string, next adk.InvokableToolCallEndpoint) adk.InvokableToolCallEndpoint {
	t.Helper()
	// Wrapping can occur per tool call; all counters must live on the run context.
	wrapped, err := mw.WrapInvokableToolCall(context.Background(), next, &adk.ToolContext{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

func readProgressArgs(t *testing.T, path string, offset, limit int) string {
	t.Helper()
	args, err := json.Marshal(map[string]any{"file_path": path, "offset": offset, "limit": limit})
	if err != nil {
		t.Fatal(err)
	}
	return string(args)
}

func assertProgressRead(t *testing.T, endpoint adk.InvokableToolCallEndpoint, ctx context.Context, args, want string) {
	t.Helper()
	got, err := endpoint(ctx, args)
	if err != nil || got != want {
		t.Fatalf("read returned %q, err=%v; want %q", got, err, want)
	}
}

func TestReadFileProgressRepeatedSuccessBudget(t *testing.T) {
	for _, name := range []string{"read_file", "eino_fs::read_file"} {
		t.Run(name, func(t *testing.T) {
			mw := newReadFileProgressMiddleware()
			ctx := readProgressContext(t, mw, context.Background())
			calls := 0
			next := func(context.Context, string, ...tool.Option) (string, error) {
				calls++
				return "original evidence must remain intact", nil
			}
			args := readProgressArgs(t, filepath.Join(t.TempDir(), "static"), 0, 165)
			for i := 1; i <= 15; i++ {
				want := "original evidence must remain intact"
				if i > readFileSameResultBudget {
					want = readFileNoProgressResult
				}
				assertProgressRead(t, wrapProgressRead(t, mw, name, next), ctx, args, want)
			}
			if calls != 15 {
				t.Fatalf("each call must check fresh content, calls=%d", calls)
			}
			state := ctx.Value(readFileProgressContextKey{}).(*readFileProgressState)
			entry := state.lru.Front().Value.(*readFileProgressEntry)
			if entry.count != readFileSameResultBudget+1 {
				t.Fatalf("counter should saturate, count=%d", entry.count)
			}
		})
	}
}

func TestReadFileProgressNormalizesPathsJSONAndDefaultPagination(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	endpoint := wrapProgressRead(t, mw, "read_file", func(context.Context, string, ...tool.Option) (string, error) {
		return "same", nil
	})
	path := filepath.Join(t.TempDir(), "space in name.txt")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	pathJSON, _ := json.Marshal(path)
	assertProgressRead(t, endpoint, ctx, `{"file_path":`+string(pathJSON)+`}`, "same")
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, relative, 0, 0), "same")
	// Construct an unclean path without filepath.Join cleaning it first.
	unclean := filepath.Dir(path) + string(os.PathSeparator) + "unused" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + filepath.Base(path)
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, unclean, -1, -3), "same")
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, 1, 2000), readFileNoProgressResult)
	// Legal whitespace in paths is significant; no TrimSpace-based collisions.
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, filepath.Join(filepath.Dir(path), " "+filepath.Base(path)), 1, 2000), "same")
}

func TestReadFileProgressSeparatesFilesPaginationAndToolNames(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	next := func(context.Context, string, ...tool.Option) (string, error) { return "same", nil }
	endpoint := wrapProgressRead(t, mw, "read_file", next)
	path := filepath.Join(t.TempDir(), "file")
	base := readProgressArgs(t, path, 0, 165)
	for i := 0; i < readFileSameResultBudget; i++ {
		assertProgressRead(t, endpoint, ctx, base, "same")
	}
	assertProgressRead(t, endpoint, ctx, base, readFileNoProgressResult)
	for _, args := range []string{
		readProgressArgs(t, path, 165, 120),
		readProgressArgs(t, path, 0, 161),
		readProgressArgs(t, path+"-other", 0, 165),
	} {
		for i := 0; i < readFileSameResultBudget; i++ {
			assertProgressRead(t, endpoint, ctx, args, "same")
		}
		assertProgressRead(t, endpoint, ctx, args, readFileNoProgressResult)
	}
	assertProgressRead(t, wrapProgressRead(t, mw, "eino_fs::read_file", next), ctx, base, "same")
}

func TestReadFileProgressChangedResultResetsWithoutNativeFile(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	result := "first evidence"
	endpoint := wrapProgressRead(t, mw, "read_file", func(context.Context, string, ...tool.Option) (string, error) { return result, nil })
	args := readProgressArgs(t, filepath.Join(t.TempDir(), "virtual-not-on-disk"), 1, 165)
	for _, content := range []string{"first evidence", "updated evidence", "first evidence"} {
		result = content
		for i := 0; i < readFileSameResultBudget; i++ {
			assertProgressRead(t, endpoint, ctx, args, content)
		}
		assertProgressRead(t, endpoint, ctx, args, readFileNoProgressResult)
	}
}

func TestReadFileProgressNativeVersionChangeAllowsUnchangedPage(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("same first page\nold second page"), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := wrapProgressRead(t, mw, "read_file", func(context.Context, string, ...tool.Option) (string, error) { return "same first page", nil })
	args := readProgressArgs(t, path, 1, 1)
	for i := 0; i < readFileSameResultBudget; i++ {
		assertProgressRead(t, endpoint, ctx, args, "same first page")
	}
	assertProgressRead(t, endpoint, ctx, args, readFileNoProgressResult)
	before := readFileVersionOf(path)
	// Same size, but a modified file version outside the requested fragment.
	if err := os.WriteFile(path, []byte("same first page\nnew second page"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(0, before.modTime).Add(2 * time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if readFileVersionOf(path) == before {
		t.Fatal("test did not change file version")
	}
	for i := 0; i < readFileSameResultBudget; i++ {
		assertProgressRead(t, endpoint, ctx, args, "same first page")
	}
	assertProgressRead(t, endpoint, ctx, args, readFileNoProgressResult)
	// A size change also resets even if the modification timestamp is retained.
	if err := os.WriteFile(path, []byte("same first page\nlonger second page"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	assertProgressRead(t, endpoint, ctx, args, "same first page")
}

func TestReadFileProgressIsolatesRunsAndInheritedAgentContext(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	endpoint := wrapProgressRead(t, mw, "read_file", func(context.Context, string, ...tool.Option) (string, error) { return "same", nil })
	args := readProgressArgs(t, filepath.Join(t.TempDir(), "file"), 0, 165)
	for i := 0; i < readFileSameResultBudget; i++ {
		assertProgressRead(t, endpoint, ctx, args, "same")
	}
	assertProgressRead(t, endpoint, ctx, args, readFileNoProgressResult)
	for _, fresh := range []context.Context{
		readProgressContext(t, mw, context.Background()),             // same middleware, new run
		readProgressContext(t, mw, ctx),                              // shared middleware, child run
		readProgressContext(t, newReadFileProgressMiddleware(), ctx), // different specialist
	} {
		for i := 0; i < readFileSameResultBudget; i++ {
			assertProgressRead(t, endpoint, fresh, args, "same")
		}
		assertProgressRead(t, endpoint, fresh, args, readFileNoProgressResult)
	}
	assertProgressRead(t, endpoint, ctx, args, readFileNoProgressResult)
	// Missing run initialization is a transparent pass-through, not global state.
	for i := 0; i < 5; i++ {
		assertProgressRead(t, endpoint, context.Background(), args, "same")
	}
}

func TestReadFileProgressPreservesFailuresCancellationAndOptions(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	wantErr := errors.New("native read failed")
	fail := true
	type testOptions struct{ Value int }
	option := tool.WrapImplSpecificOptFn(func(o *testOptions) { o.Value = 42 })
	endpoint := wrapProgressRead(t, mw, "read_file", func(_ context.Context, _ string, opts ...tool.Option) (string, error) {
		if len(opts) != 1 || tool.GetImplSpecificOptions[testOptions](nil, opts...).Value != 42 {
			t.Fatalf("options not forwarded: %d", len(opts))
		}
		if fail {
			return "partial evidence", wantErr
		}
		return "same", nil
	})
	args := readProgressArgs(t, filepath.Join(t.TempDir(), "file"), 0, 165)
	for i := 0; i < 5; i++ {
		got, err := endpoint(ctx, args, option)
		if got != "partial evidence" || err != wantErr {
			t.Fatalf("error/result changed: %q %v", got, err)
		}
	}
	fail = false
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	for i := 0; i < 5; i++ {
		got, err := endpoint(cancelCtx, args, option)
		if got != "same" || err != nil {
			t.Fatalf("canceled result changed: %q %v", got, err)
		}
	}
	for i := 0; i < readFileSameResultBudget; i++ {
		got, err := endpoint(ctx, args, option)
		if got != "same" || err != nil {
			t.Fatalf("failures consumed success budget: %q %v", got, err)
		}
	}
	got, err := endpoint(ctx, args, option)
	if got != readFileNoProgressResult || err != nil {
		t.Fatalf("success budget not enforced: %q %v", got, err)
	}
}

func TestReadFileProgressLeavesOtherToolsAndUnknownSchemasUnchanged(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	next := func(context.Context, string, ...tool.Option) (string, error) { return "same", nil }
	for _, name := range []string{"grep", "execute", "write_file", "external::read_file"} {
		endpoint := wrapProgressRead(t, mw, name, next)
		for i := 0; i < 5; i++ {
			assertProgressRead(t, endpoint, ctx, `{"file_path":"file"}`, "same")
		}
	}
	endpoint := wrapProgressRead(t, mw, "read_file", next)
	for _, args := range []string{`{`, `[]`, `null`, `{}`, `{"path":"file"}`, `{"file_path":"file","offset":"1"}`} {
		for i := 0; i < 5; i++ {
			assertProgressRead(t, endpoint, ctx, args, "same")
		}
	}
	state := ctx.Value(readFileProgressContextKey{}).(*readFileProgressState)
	if len(state.entries) != 0 {
		t.Fatalf("unrelated calls recorded: %d", len(state.entries))
	}
}

func TestReadFileProgressBoundedLRU(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	endpoint := wrapProgressRead(t, mw, "read_file", func(context.Context, string, ...tool.Option) (string, error) { return "same", nil })
	path := filepath.Join(t.TempDir(), "file")
	for i := 1; i <= readFileProgressMaxEntries; i++ {
		assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, i, 1), "same")
	}
	// Keep fragment 1 recent so fragment 2 is evicted instead.
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, 1, 1), "same")
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, readFileProgressMaxEntries+1, 1), "same")
	state := ctx.Value(readFileProgressContextKey{}).(*readFileProgressState)
	key2, _ := normalizeReadFileFragment("read_file", readProgressArgs(t, path, 2, 1))
	if len(state.entries) != readFileProgressMaxEntries || state.lru.Len() != readFileProgressMaxEntries || state.entries[key2] != nil {
		t.Fatalf("LRU bound/eviction failed: map=%d list=%d", len(state.entries), state.lru.Len())
	}
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, 1, 1), "same")
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, 1, 1), readFileNoProgressResult)
	assertProgressRead(t, endpoint, ctx, readProgressArgs(t, path, 2, 1), "same")
}

func TestReadFileProgressConcurrentSuccesses(t *testing.T) {
	mw := newReadFileProgressMiddleware()
	ctx := readProgressContext(t, mw, context.Background())
	var nativeCalls, originalResults, hints atomic.Int32
	endpoint := wrapProgressRead(t, mw, "read_file", func(context.Context, string, ...tool.Option) (string, error) {
		nativeCalls.Add(1)
		return "same", nil
	})
	args := readProgressArgs(t, filepath.Join(t.TempDir(), "file"), 1, 165)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := endpoint(ctx, args)
			if err != nil {
				t.Errorf("read failed: %v", err)
				return
			}
			switch got {
			case "same":
				originalResults.Add(1)
			case readFileNoProgressResult:
				hints.Add(1)
			default:
				t.Errorf("unexpected result %q", got)
			}
		}()
	}
	wg.Wait()
	if nativeCalls.Load() != 40 || originalResults.Load() != readFileSameResultBudget || hints.Load() != 40-readFileSameResultBudget {
		t.Fatalf("concurrent budget: native=%d original=%d hints=%d", nativeCalls.Load(), originalResults.Load(), hints.Load())
	}
}

// Stateless mock model drives actual ADK invocation rather than calling hooks
// directly; the same agent/model/middleware can safely be reused for another run.
type readProgressTestModel struct{ arguments string }

func (m *readProgressTestModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}
func (m *readProgressTestModel) Generate(_ context.Context, messages []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	reads := 0
	for _, message := range messages {
		if message.Role == schema.Tool {
			reads++
		}
	}
	if reads >= 5 {
		return schema.AssistantMessage("done", nil), nil
	}
	return schema.AssistantMessage("", []schema.ToolCall{{ID: fmt.Sprintf("read-%d", reads), Type: "function", Function: schema.FunctionCall{Name: "read_file", Arguments: m.arguments}}}), nil
}
func (m *readProgressTestModel) Stream(ctx context.Context, messages []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	message, err := m.Generate(ctx, messages, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{message}), nil
}

func TestReadFileProgressReductionStaticFileAuditReproduction(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "call_static_evidence")
	lines := make([]string, 237)
	for i := range lines {
		lines[i] = "0123456789abcdef"
	}
	lines[0], lines[1] = "original evidence", "second line"
	content := strings.Join(lines, "\n")
	content += strings.Repeat("x", 4125-len(content))
	if len(content) != 4125 || len(strings.Split(content, "\n")) != 237 {
		t.Fatal("audit fixture must contain 237 lines and 4125 bytes")
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx = workspaceguard.WithPolicy(ctx, &workspaceguard.Policy{
		Workspace: t.TempDir(), ReadOnlyRoots: []string{filepath.Dir(path)},
	})
	backend, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	filesystemMW, err := reductionReadFileMiddleware(ctx, backend)
	if err != nil {
		t.Fatal(err)
	}
	_, runCtx, err := filesystemMW.BeforeAgent(ctx, &adk.ChatModelAgentContext{})
	if err != nil {
		t.Fatal(err)
	}
	readTool, ok := runCtx.Tools[0].(tool.InvokableTool)
	if !ok {
		t.Fatal("native reduction read_file must be invokable")
	}
	mw := newReadFileProgressMiddleware()
	ctx = readProgressContext(t, mw, ctx)
	endpoint := wrapProgressRead(t, mw, "read_file", readTool.InvokableRun)
	for _, sequence := range []struct{ limit, repeats int }{{165, 15}, {161, 5}} {
		args := readProgressArgs(t, path, 0, sequence.limit)
		original, err := readTool.InvokableRun(ctx, args)
		if err != nil || !strings.Contains(original, "original evidence") {
			t.Fatalf("native evidence read failed: %q %v", original, err)
		}
		for i := 0; i < sequence.repeats; i++ {
			want := original
			if i >= readFileSameResultBudget {
				want = readFileNoProgressResult
			}
			assertProgressRead(t, endpoint, ctx, args, want)
		}
	}
	page := readProgressArgs(t, path, 165, 120)
	original, err := readTool.InvokableRun(ctx, page)
	if err != nil {
		t.Fatal(err)
	}
	assertProgressRead(t, endpoint, ctx, page, original)
}

func TestReadFileProgressADKReductionReadIntegration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persisted-evidence")
	if err := os.WriteFile(path, []byte("original evidence\nsecond line"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx = workspaceguard.WithPolicy(ctx, &workspaceguard.Policy{
		Workspace: t.TempDir(), ReadOnlyRoots: []string{filepath.Dir(path)},
	})
	backend, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	filesystemMW, err := reductionReadFileMiddleware(ctx, backend)
	if err != nil {
		t.Fatal(err)
	}
	// Use the same helper as single, Deep, supervisor, specialist and executor.
	handlers := appendEinoChatModelTailMiddlewares([]adk.ChatModelAgentMiddleware{filesystemMW}, einoChatModelTailConfig{skipTelemetry: true, skipTrace: true})
	chatAgent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name: "read_progress_test", Description: "test", MaxIterations: 8,
		Model: &readProgressTestModel{arguments: readProgressArgs(t, path, 0, 165)}, Handlers: handlers,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, streaming := range []bool{false, true} {
		iterator := chatAgent.Run(ctx, &adk.AgentInput{Messages: []adk.Message{schema.UserMessage("read")}, EnableStreaming: streaming})
		var outputs []string
		for {
			event, ok := iterator.Next()
			if !ok {
				break
			}
			if event.Err != nil {
				t.Fatalf("ADK run failed: %v", event.Err)
			}
			if event.Output == nil || event.Output.MessageOutput == nil {
				continue
			}
			message, err := event.Output.MessageOutput.GetMessage()
			if err != nil {
				t.Fatal(err)
			}
			if message.Role == schema.Tool {
				outputs = append(outputs, message.Content)
			}
		}
		if len(outputs) != 5 {
			t.Fatalf("streaming=%v expected 5 reads, got %d", streaming, len(outputs))
		}
		for i, output := range outputs {
			if i < readFileSameResultBudget {
				if !strings.Contains(output, "original evidence") || !strings.Contains(output, "second line") {
					t.Fatalf("read %d lost original evidence: %q", i+1, output)
				}
			} else if output != readFileNoProgressResult {
				t.Fatalf("read %d missing hint: %q", i+1, output)
			}
		}
	}
}
