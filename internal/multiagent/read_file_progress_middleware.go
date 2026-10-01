package multiagent

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
)

const (
	readFileSameResultBudget   = 3
	readFileProgressMaxEntries = 128
	readFileNoProgressPrefix   = "[Read File No Progress]"
	readFileNoProgressResult   = readFileNoProgressPrefix + " 已读、无进展：该文件片段的相同结果已成功返回 3 次，本次读取确认没有新增信息，不再重放正文。请使用已有证据推进；只有需要尚未读取的内容时才读取其他分页。文件或结果变化后可重新读取。此提示不代表任务完成或覆盖成功。"
)

// readFileProgressMiddleware observes successful native filesystem reads before
// outer reduction handlers can offload their results. It is deliberately not a
// cache: always invoke the tool first so a changed result can pass through intact.
// Eino v0.8.13 filesystem/reduction read_file tools are InvokableTool, including
// when the agent streams model output. Other tools and streaming tools stay as-is.
type readFileProgressMiddleware struct {
	adk.BaseChatModelAgentMiddleware
}

type readFileProgressContextKey struct{}

func newReadFileProgressMiddleware() adk.ChatModelAgentMiddleware {
	return &readFileProgressMiddleware{}
}

// A fresh state shadows any inherited parent-agent state on every Run/Resume.
// Counters are neither global nor stored on a reusable middleware/agent instance.
// They are intentionally ephemeral (not checkpoint data), with bounded memory.
func (m *readFileProgressMiddleware) BeforeAgent(ctx context.Context, runCtx *adk.ChatModelAgentContext) (context.Context, *adk.ChatModelAgentContext, error) {
	state := &readFileProgressState{
		entries: make(map[readFileFragment]*list.Element),
		lru:     list.New(),
	}
	return context.WithValue(ctx, readFileProgressContextKey{}, state), runCtx, nil
}

func (m *readFileProgressMiddleware) WrapInvokableToolCall(_ context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	if tCtx == nil || (tCtx.Name != "read_file" && tCtx.Name != "eino_fs::read_file") {
		return endpoint, nil
	}
	name := tCtx.Name
	return func(ctx context.Context, arguments string, opts ...tool.Option) (string, error) {
		result, err := endpoint(ctx, arguments, opts...)
		if err != nil || ctx.Err() != nil {
			return result, err
		}
		state, _ := ctx.Value(readFileProgressContextKey{}).(*readFileProgressState)
		if state == nil {
			return result, nil
		}
		fragment, ok := normalizeReadFileFragment(name, arguments)
		if !ok {
			// Unknown schemas must not accidentally consume another read's budget.
			return result, nil
		}
		if state.observe(fragment, sha256.Sum256([]byte(result)), readFileVersionOf(fragment.path)) {
			return readFileNoProgressResult, nil
		}
		return result, nil
	}, nil
}

type readFileFragment struct {
	name   string
	path   string
	offset int
	limit  int
}

func normalizeReadFileFragment(name, arguments string) (readFileFragment, bool) {
	var args struct {
		FilePath string `json:"file_path"`
		Offset   int    `json:"offset"`
		Limit    int    `json:"limit"`
	}
	if json.Unmarshal([]byte(arguments), &args) != nil || args.FilePath == "" {
		return readFileFragment{}, false
	}
	// Match the pinned Eino filesystem defaults exactly; do not trim valid
	// whitespace in paths, resolve symlinks, or alter arguments sent to the tool.
	path, err := filepath.Abs(args.FilePath)
	if err != nil {
		return readFileFragment{}, false
	}
	if args.Offset <= 0 {
		args.Offset = 1
	}
	if args.Limit <= 0 {
		args.Limit = 2000
	}
	return readFileFragment{name: name, path: filepath.Clean(path), offset: args.Offset, limit: args.Limit}, true
}

// Native metadata is only an additional reset signal. A virtual backend or
// failed Stat still uses the exact result digest and never prevents a new result.
type readFileVersion struct {
	known   bool
	modTime int64
	size    int64
}

func readFileVersionOf(path string) readFileVersion {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return readFileVersion{}
	}
	return readFileVersion{known: true, modTime: info.ModTime().UnixNano(), size: info.Size()}
}

type readFileProgressEntry struct {
	fragment readFileFragment
	digest   [sha256.Size]byte
	version  readFileVersion
	count    int
}

type readFileProgressState struct {
	mu      sync.Mutex
	entries map[readFileFragment]*list.Element
	lru     *list.List
}

// observe returns true only after the exact same successful fragment has already
// been delivered within budget. It retains no file contents, saturates counters,
// and evicts the least-recently-used fragment (evicted fragments get a new budget).
func (s *readFileProgressState) observe(fragment readFileFragment, digest [sha256.Size]byte, version readFileVersion) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.entries[fragment]; ok {
		entry := element.Value.(*readFileProgressEntry)
		s.lru.MoveToFront(element)
		if entry.digest != digest || entry.version != version {
			entry.digest, entry.version, entry.count = digest, version, 1
		} else if entry.count <= readFileSameResultBudget {
			entry.count++
		}
		return entry.count > readFileSameResultBudget
	}
	if len(s.entries) >= readFileProgressMaxEntries {
		oldest := s.lru.Back()
		delete(s.entries, oldest.Value.(*readFileProgressEntry).fragment)
		s.lru.Remove(oldest)
	}
	entry := &readFileProgressEntry{fragment: fragment, digest: digest, version: version, count: 1}
	s.entries[fragment] = s.lru.PushFront(entry)
	return false
}
