package multiagent

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
)

const (
	sessionContextMaxSkills   = 64
	sessionContextMaxRefs     = 256
	sessionContextSkillPrefix = "[Skill 已在会话上下文中]"
	sessionContextRefPrefix   = "[Reference 已在会话上下文中]"

	// skillReferenceMinBytes keeps the rule off files too small for a repeat
	// send to matter. Suppressing a short file would complicate debugging for no
	// real saving, and the existing read_file guard already covers trivial repeats.
	skillReferenceMinBytes = 512
)

// Skill body headings emitted by the pinned Eino skill middleware (v0.8.13).
// Both the launch line and the body heading must be recognised: the heading is
// what makes a tool result a skill body, the launch line carries the name.
const (
	skillBodyHeading        = "## 技能正文"
	skillBodyHeadingEnglish = "## Skill Content"
	skillLaunchPrefix       = "正在启动 Skill："
	skillLaunchPrefixEn     = "Launching skill: "
)

// sessionContextMiddleware keeps a session-level record of skill bodies and
// reference files already injected into the conversation.
//
// The waste it removes is specific and recurring: a role loads a skill, later
// turns load the same skill again, and every repeat re-sends the entire body as
// a fresh tool result. The same holds for a reference file read a fifth and
// sixth time. The body is already in the conversation context, so re-sending it
// adds no information and consumes the window the actual task needs.
//
// Design constraints, in order of importance:
//
//  1. The tool is still invoked. Deduplication is decided from the real result,
//     so a changed SKILL.md or reference file passes through untouched.
//     Suppressing a genuinely changed body would hide new instructions, which is
//     a correctness bug rather than a bandwidth saving.
//  2. The notice is only a notice. It never claims the task is complete, never
//     reports coverage, and never substitutes for evidence.
//  3. The record is bounded and per-run. Memory is capped, entries are evicted
//     least-recently-used first, and nothing is persisted as checkpoint data.
type sessionContextMiddleware struct {
	adk.BaseChatModelAgentMiddleware
}

type sessionContextStateKey struct{}

// sessionContextState is created per Run/Resume. It is not shared between agents
// and not stored on the middleware instance, because separate runs of the same
// agent must not inherit each other's "already loaded" conclusions.
type sessionContextState struct {
	mu       sync.Mutex
	skills   map[string]*list.Element
	skillLRU *list.List
	refs     map[string]*list.Element
	refLRU   *list.List
}

type sessionContextEntry struct {
	key    string
	digest [sha256.Size]byte
	bytes  int
}

func newSessionContextMiddleware() adk.ChatModelAgentMiddleware {
	return &sessionContextMiddleware{}
}

func (m *sessionContextMiddleware) BeforeAgent(ctx context.Context, runCtx *adk.ChatModelAgentContext) (context.Context, *adk.ChatModelAgentContext, error) {
	// The record starts empty for every run.
	//
	// It is deliberately not seeded from conversation history. adk.ChatModelAgentContext
	// exposes the instruction and tools but not the messages, so a middleware at this
	// layer cannot tell whether a previously injected body is still present. Guessing
	// would be worse than re-sending once: after summarization drops a body, a seeded
	// "already in context" notice would point the model at content it can no longer
	// read. Deduplication therefore covers repeats within one run, which is where the
	// repeated loads actually happen.
	state := &sessionContextState{
		skills:   make(map[string]*list.Element),
		skillLRU: list.New(),
		refs:     make(map[string]*list.Element),
		refLRU:   list.New(),
	}
	return context.WithValue(ctx, sessionContextStateKey{}, state), runCtx, nil
}

func (m *sessionContextMiddleware) WrapInvokableToolCall(_ context.Context, endpoint adk.InvokableToolCallEndpoint, tCtx *adk.ToolContext) (adk.InvokableToolCallEndpoint, error) {
	if tCtx == nil {
		return endpoint, nil
	}
	kind := sessionContextToolKind(tCtx.Name)
	if kind == sessionContextToolUnknown {
		return endpoint, nil
	}
	return func(ctx context.Context, arguments string, opts ...tool.Option) (string, error) {
		result, err := endpoint(ctx, arguments, opts...)
		if err != nil || ctx.Err() != nil {
			return result, err
		}
		state, _ := ctx.Value(sessionContextStateKey{}).(*sessionContextState)
		if state == nil {
			return result, nil
		}
		switch kind {
		case sessionContextToolSkill:
			return state.noteSkill(result, arguments), nil
		case sessionContextToolReference:
			return state.noteReference(result, arguments), nil
		}
		return result, nil
	}, nil
}

type sessionContextToolClass int

const (
	sessionContextToolUnknown sessionContextToolClass = iota
	sessionContextToolSkill
	sessionContextToolReference
)

// sessionContextToolKind classifies the wrapped tool.
//
// read_file is only treated as a reference read when the path is a skill package
// file. The same tool reads ordinary source and evidence files, where the
// existing read_file progress guard already owns the repetition policy and a
// competing rule would make behaviour harder to reason about.
func sessionContextToolKind(name string) sessionContextToolClass {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return sessionContextToolUnknown
	}
	base := trimmed
	if index := strings.LastIndex(base, "::"); index >= 0 {
		base = base[index+2:]
	}
	switch base {
	case "skill", "load_skill":
		return sessionContextToolSkill
	case "read_file":
		return sessionContextToolReference
	}
	return sessionContextToolUnknown
}

// noteSkill records an injected skill body and replaces a repeat injection.
//
// A skill using context: fork or fork_with_context runs a sub-agent and returns
// that sub-agent's result instead of a body. That result is new information on
// every call, so it is never deduplicated.
func (s *sessionContextState) noteSkill(result, arguments string) string {
	if strings.Contains(result, "completed (sub-agent execution)") ||
		strings.Contains(result, "已完成（子 Agent 执行）") {
		return result
	}
	name := skillNameFromResult(result)
	if name == "" {
		name = skillNameFromArguments(arguments)
	}
	if name == "" || !isSkillBody(result) {
		return result
	}
	digest := sha256.Sum256([]byte(result))
	previous, seen := s.observeSkill(strings.ToLower(name), digest, len(result))
	if !seen {
		return result
	}
	return sessionContextSkillNotice(name, previous, len(result))
}

// noteReference records a reference file body and replaces a repeat read.
func (s *sessionContextState) noteReference(result, arguments string) string {
	path := readFilePathFromArguments(arguments)
	if path == "" || !looksLikeSkillReference(path, result) {
		return result
	}
	digest := sha256.Sum256([]byte(result))
	previous, seen := s.observeRef(path, digest, len(result))
	if !seen {
		return result
	}
	return sessionContextReferenceNotice(path, previous, len(result))
}

func sessionContextSkillNotice(name string, previous, current int) string {
	return strings.Join([]string{
		sessionContextSkillPrefix + "：本会话已经注入过 skill " + name + " 的正文（" + sizeText(previous) + "）。",
		"本次调用已完成校验：正文与上一次注入完全相同（" + sizeText(current) + "），因此不再重发全文。",
		"请直接使用上下文中已有的正文继续；如需脚本、reference 或资源文件，按正文给出的相对路径另行读取。",
		"此提示只说明重复注入被跳过，不代表任务完成，也不代表任何覆盖或验证结论。",
	}, "\n")
}

func sessionContextReferenceNotice(path string, previous, current int) string {
	return strings.Join([]string{
		sessionContextRefPrefix + "：本会话已经注入过该 reference 的相同内容（" + path + "）。",
		"本次读取确认内容未变化（" + sizeText(current) + "），因此不再重发全文。",
		"请使用上下文中已有内容继续；只有需要文件的其他部分、或文件已被修改时才重新读取。",
		"此提示只说明重复内容被跳过，不代表任务完成或证据充分。",
	}, "\n")
}

func sizeText(bytes int) string {
	return strconv.Itoa(bytes) + " 字节"
}

// observeSkill records a skill body. It returns the byte count injected last
// time and whether this body was already injected with identical content.
func (s *sessionContextState) observeSkill(key string, digest [sha256.Size]byte, size int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return observeBounded(s.skills, s.skillLRU, key, digest, size, sessionContextMaxSkills)
}

func (s *sessionContextState) observeRef(key string, digest [sha256.Size]byte, size int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return observeBounded(s.refs, s.refLRU, key, digest, size, sessionContextMaxRefs)
}

func observeBounded(index map[string]*list.Element, lru *list.List, key string, digest [sha256.Size]byte, size, max int) (int, bool) {
	if element, ok := index[key]; ok {
		entry := element.Value.(*sessionContextEntry)
		lru.MoveToFront(element)
		if entry.digest == digest {
			return entry.bytes, true
		}
		// Content changed: the new body must reach the model intact.
		entry.digest, entry.bytes = digest, size
		return 0, false
	}
	if max > 0 && len(index) >= max {
		if oldest := lru.Back(); oldest != nil {
			delete(index, oldest.Value.(*sessionContextEntry).key)
			lru.Remove(oldest)
		}
	}
	index[key] = lru.PushFront(&sessionContextEntry{key: key, digest: digest, bytes: size})
	return 0, false
}

// isSkillBody reports whether a tool result carries an injected skill body.
func isSkillBody(result string) bool {
	return strings.Contains(result, skillBodyHeading) ||
		strings.Contains(result, skillBodyHeadingEnglish) ||
		strings.Contains(result, "Base directory for this skill") ||
		strings.Contains(result, "此 Skill 的目录")
}

// skillNameFromResult reads the name from the middleware's launch line, which
// precedes the body heading in every inline skill result.
func skillNameFromResult(result string) string {
	for _, prefix := range []string{skillLaunchPrefix, skillLaunchPrefixEn} {
		if index := strings.Index(result, prefix); index >= 0 {
			rest := result[index+len(prefix):]
			if end := strings.IndexAny(rest, "\r\n"); end >= 0 {
				rest = rest[:end]
			}
			if name := strings.TrimSpace(rest); name != "" {
				return name
			}
		}
	}
	return ""
}

func skillNameFromArguments(arguments string) string {
	var args struct {
		Skill string `json:"skill"`
		Name  string `json:"name"`
	}
	if json.Unmarshal([]byte(arguments), &args) != nil {
		return ""
	}
	if name := strings.TrimSpace(args.Skill); name != "" {
		return name
	}
	return strings.TrimSpace(args.Name)
}

func readFilePathFromArguments(arguments string) string {
	var args struct {
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
	}
	if json.Unmarshal([]byte(arguments), &args) != nil {
		return ""
	}
	for _, candidate := range []string{args.FilePath, args.Path} {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		if absolute, err := filepath.Abs(trimmed); err == nil {
			return filepath.Clean(absolute)
		}
		return filepath.Clean(trimmed)
	}
	return ""
}

// looksLikeSkillReference decides whether a read result is a skill package file.
//
// The path must exist, sit under a skills directory, and belong to one of the
// package's auxiliary directories. Anything else — evidence files, source
// trees, persisted tool output — keeps normal read behaviour.
func looksLikeSkillReference(path, result string) bool {
	if len(result) < skillReferenceMinBytes {
		return false
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return false
	}
	cleaned := filepath.ToSlash(path)
	if !strings.Contains(cleaned, "/skills/") && !strings.HasPrefix(cleaned, "skills/") {
		return false
	}
	for _, dir := range []string{"/references/", "/scripts/", "/assets/"} {
		if strings.Contains(cleaned, dir) {
			return true
		}
	}
	return false
}

// seedFromMessages was intentionally removed together with history seeding.
// adk.ChatModelAgentContext does not expose messages, so no caller can supply a
// trustworthy "already injected" set at this layer. A future version could seed
// from the model input path, where messages are available, but only together
// with a check that the body is still present rather than summarized away.
