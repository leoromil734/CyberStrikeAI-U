package multiagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
)

func sessionContextRun(t *testing.T, mw adk.ChatModelAgentMiddleware) context.Context {
	t.Helper()
	runCtx := &adk.ChatModelAgentContext{Instruction: "unchanged"}
	ctx, got, err := mw.BeforeAgent(context.Background(), runCtx)
	if err != nil || got != runCtx {
		t.Fatalf("BeforeAgent must not replace the run context: %v", err)
	}
	return ctx
}

func sessionContextWrap(t *testing.T, mw adk.ChatModelAgentMiddleware, name string, next adk.InvokableToolCallEndpoint) adk.InvokableToolCallEndpoint {
	t.Helper()
	wrapped, err := mw.WrapInvokableToolCall(context.Background(), next, &adk.ToolContext{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

// skillResult mimics the pinned Eino skill middleware's inline result shape.
func skillResult(name, body string) string {
	return "正在启动 Skill：" + name + "\n\n此 Skill 的目录：/skills/" + name + "\n\n## 技能正文\n\n" + body
}

func callArgs(t *testing.T, args map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func writeTestFile(t *testing.T, path, content string) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestSessionContextSkillSecondLoadReturnsNotice(t *testing.T) {
	mw := newSessionContextMiddleware()
	ctx := sessionContextRun(t, mw)
	body := strings.Repeat("detailed skill instructions. ", 40)
	calls := 0
	next := func(context.Context, string, ...tool.Option) (string, error) {
		calls++
		return skillResult("pentest-blackboard", body), nil
	}
	args := callArgs(t, map[string]any{"skill": "pentest-blackboard"})

	first, err := sessionContextWrap(t, mw, "skill", next)(ctx, args)
	if err != nil || first != skillResult("pentest-blackboard", body) {
		t.Fatalf("first load must return the full body: %v", err)
	}
	second, err := sessionContextWrap(t, mw, "skill", next)(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(second, sessionContextSkillPrefix) {
		t.Fatalf("second load must be replaced by a notice, got %q", second)
	}
	if strings.Contains(second, body) {
		t.Fatal("the notice must not re-send the body")
	}
	for _, required := range []string{"pentest-blackboard", "不代表任务完成"} {
		if !strings.Contains(second, required) {
			t.Errorf("notice must state %q: %s", required, second)
		}
	}
	// The tool is always invoked: deduplication is decided from real content.
	if calls != 2 {
		t.Fatalf("every call must still reach the tool, calls=%d", calls)
	}
}

func TestSessionContextSkillChangedBodyPassesThrough(t *testing.T) {
	mw := newSessionContextMiddleware()
	ctx := sessionContextRun(t, mw)
	revision := 0
	next := func(context.Context, string, ...tool.Option) (string, error) {
		revision++
		return skillResult("recon", strings.Repeat("v", 100)+string(rune('0'+revision))), nil
	}
	args := callArgs(t, map[string]any{"skill": "recon"})
	if _, err := sessionContextWrap(t, mw, "skill", next)(ctx, args); err != nil {
		t.Fatal(err)
	}
	second, err := sessionContextWrap(t, mw, "skill", next)(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(second, sessionContextSkillPrefix) {
		t.Fatal("a changed skill body must never be suppressed")
	}
	if !strings.Contains(second, "## 技能正文") {
		t.Fatalf("changed body must be delivered intact: %q", second)
	}
}

func TestSessionContextForkedSkillIsNeverDeduplicated(t *testing.T) {
	mw := newSessionContextMiddleware()
	ctx := sessionContextRun(t, mw)
	next := func(context.Context, string, ...tool.Option) (string, error) {
		return `Skill "pdf" 已完成（子 Agent 执行）。

结果：分析输出 ` + strings.Repeat("x", 200), nil
	}
	args := callArgs(t, map[string]any{"skill": "pdf"})
	for i := 0; i < 2; i++ {
		got, err := sessionContextWrap(t, mw, "skill", next)(ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(got, sessionContextSkillPrefix) {
			t.Fatal("a forked sub-agent result is new information on every call")
		}
	}
}

func TestSessionContextReferenceSecondReadReturnsNotice(t *testing.T) {
	mw := newSessionContextMiddleware()
	ctx := sessionContextRun(t, mw)
	root := t.TempDir()
	path := root + "/skills/pentest-blackboard/references/coverage-contract.md"
	if err := writeTestFile(t, path, strings.Repeat("# contract\n", 80)); err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("# contract\n", 80)
	next := func(context.Context, string, ...tool.Option) (string, error) { return content, nil }
	args := callArgs(t, map[string]any{"file_path": path})

	if got, err := sessionContextWrap(t, mw, "read_file", next)(ctx, args); err != nil || got != content {
		t.Fatalf("first read must return the file: %v", err)
	}
	second, err := sessionContextWrap(t, mw, "read_file", next)(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(second, sessionContextRefPrefix) {
		t.Fatalf("repeat reference read must be a notice, got %q", second)
	}
}

func TestSessionContextOrdinaryReadFileIsUntouched(t *testing.T) {
	mw := newSessionContextMiddleware()
	ctx := sessionContextRun(t, mw)
	root := t.TempDir()
	path := root + "/evidence/notes.txt"
	content := strings.Repeat("ordinary evidence line\n", 60)
	if err := writeTestFile(t, path, content); err != nil {
		t.Fatal(err)
	}
	next := func(context.Context, string, ...tool.Option) (string, error) { return content, nil }
	args := callArgs(t, map[string]any{"file_path": path})
	for i := 0; i < 3; i++ {
		got, err := sessionContextWrap(t, mw, "read_file", next)(ctx, args)
		if err != nil || got != content {
			t.Fatalf("non-skill reads must keep normal behaviour: %v", err)
		}
	}
}

// The record is per run by design: adk.ChatModelAgentContext exposes the
// instruction and tools but not the messages, so a middleware at this layer
// cannot tell whether an earlier run's body is still in context. A resumed run
// therefore gets the body again, which is the safe direction — re-sending costs
// tokens, while a seeded "already loaded" notice after summarization would point
// the model at content it can no longer read.
func TestSessionContextIsPerRunNotPerHistory(t *testing.T) {
	mw := newSessionContextMiddleware()
	body := strings.Repeat("resumed skill body. ", 40)
	next := func(context.Context, string, ...tool.Option) (string, error) {
		return skillResult("pentest-blackboard", body), nil
	}
	args := callArgs(t, map[string]any{"skill": "pentest-blackboard"})
	first := sessionContextRun(t, mw)
	if got, err := sessionContextWrap(t, mw, "skill", next)(first, args); err != nil || got != skillResult("pentest-blackboard", body) {
		t.Fatalf("first run must deliver the body: %v", err)
	}
	// A second run starts a new record, so its first load is a real load.
	second := sessionContextRun(t, mw)
	got, err := sessionContextWrap(t, mw, "skill", next)(second, args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(got, sessionContextSkillPrefix) {
		t.Fatalf("a new run must not inherit the previous run's dedup record: %q", got)
	}
	if !strings.Contains(got, "## 技能正文") {
		t.Fatalf("second run's first load must carry the body: %q", got)
	}
}

// Within one run the notice must only ever appear for identical content, never
// for a body the run has not actually seen.
func TestSessionContextNoticeRequiresPriorInjectionInSameRun(t *testing.T) {
	mw := newSessionContextMiddleware()
	ctx := sessionContextRun(t, mw)
	body := strings.Repeat("body. ", 60)
	next := func(context.Context, string, ...tool.Option) (string, error) {
		return skillResult("pentest-blackboard", body), nil
	}
	got, err := sessionContextWrap(t, mw, "skill", next)(ctx, callArgs(t, map[string]any{"skill": "pentest-blackboard"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(got, sessionContextSkillPrefix) {
		t.Fatal("the first injection in a run must never be suppressed")
	}
}

func TestSessionContextToolKindClassification(t *testing.T) {
	cases := map[string]sessionContextToolClass{
		"skill": sessionContextToolSkill, "load_skill": sessionContextToolSkill,
		"read_file": sessionContextToolReference, "eino_fs::read_file": sessionContextToolReference,
		"exec": sessionContextToolUnknown, "execute": sessionContextToolUnknown,
		"write_file": sessionContextToolUnknown, "": sessionContextToolUnknown,
		"eino_fs::write_file": sessionContextToolUnknown,
	}
	for name, want := range cases {
		if got := sessionContextToolKind(name); got != want {
			t.Errorf("sessionContextToolKind(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSessionContextNoticeStatesSizeNotCompletion(t *testing.T) {
	notice := sessionContextSkillNotice("demo", 4096, 4096)
	if !strings.Contains(notice, "4096") {
		t.Fatalf("notice should report the previously injected size: %s", notice)
	}
	if strings.Contains(notice, "完成覆盖") || strings.Contains(notice, "已覆盖") {
		t.Fatalf("notice must not claim coverage: %s", notice)
	}
}
