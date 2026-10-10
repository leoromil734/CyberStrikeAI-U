package multiagent

import (
	"context"
	"fmt"
	"testing"

	"cyberstrike-ai/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
)

type stubChatModelAgentMiddleware struct {
	adk.BaseChatModelAgentMiddleware
	tag string
}

func stubMW(tag string) adk.ChatModelAgentMiddleware {
	return &stubChatModelAgentMiddleware{tag: tag}
}

func TestBuildPlanExecuteExecutorHandlers_IncludesExecPreMiddlewares(t *testing.T) {
	t.Parallel()
	pre := []adk.ChatModelAgentMiddleware{
		stubMW("patch"),
		stubMW("reduction"),
	}

	got, err := buildPlanExecuteExecutorHandlers(context.Background(), &PlanExecuteRootArgs{
		ExecPreMiddlewares:   pre,
		FilesystemMiddleware: stubMW("filesystem"),
		SkillMiddleware:      stubMW("skill"),
	})
	if err != nil {
		t.Fatalf("buildPlanExecuteExecutorHandlers: %v", err)
	}
	// 2 pre + fs + skill + 会话级去重。去重必须排在最后，也就是排在 skill 注入之后，
	// 否则它看到的是请求参数而不是真实正文，无法判断正文是否重复。
	if len(got) != 5 {
		t.Fatalf("expected 5 pre-tail handlers (2 pre + fs + skill + session context), got %d", len(got))
	}
	for i, want := range []string{"patch", "reduction", "filesystem", "skill"} {
		st, ok := got[i].(*stubChatModelAgentMiddleware)
		if !ok || st.tag != want {
			t.Fatalf("handler[%d]: got %#v want tag %q", i, got[i], want)
		}
	}
	if _, ok := got[4].(*sessionContextMiddleware); !ok {
		t.Fatalf("handler[4] must be the session context dedup middleware, got %#v", got[4])
	}
}

func stubTools(n int) []tool.BaseTool {
	out := make([]tool.BaseTool, n)
	for i := 0; i < n; i++ {
		out[i] = stubTool{name: fmt.Sprintf("t%d", i)}
	}
	return out
}

func TestBuildPlanExecuteExecutorHandlers_NilArgs(t *testing.T) {
	t.Parallel()
	if _, err := buildPlanExecuteExecutorHandlers(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil args")
	}
}

func TestPrependEinoMiddlewares_Main_IncludesPatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mw := configMultiAgentEinoMiddlewareForTest()
	mw.ReductionEnable = false
	mw.ToolSearchEnable = false
	mw.PlantaskEnable = false
	_, extra, _, err := prependEinoMiddlewares(ctx, mw, einoMWMain, stubTools(25), nil, "", "conv-test", "", nil)
	if err != nil {
		t.Fatalf("prependEinoMiddlewares: %v", err)
	}
	if len(extra) == 0 {
		t.Fatal("expected patch middleware on einoMWMain when patch_tool_calls enabled")
	}
}

func configMultiAgentEinoMiddlewareForTest() *config.MultiAgentEinoMiddlewareConfig {
	patch := true
	return &config.MultiAgentEinoMiddlewareConfig{
		PatchToolCalls: &patch,
	}
}
