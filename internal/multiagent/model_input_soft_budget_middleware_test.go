package multiagent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/middlewares/summarization"
	"github.com/cloudwego/eino/schema"
)

func budgetFixtureCounter(_ context.Context, in *summarization.TokenCounterInput) (int, error) {
	n := 0
	for _, msg := range in.Messages {
		if msg != nil {
			n += utf8.RuneCountInString(msg.Content) + len(msg.ToolCalls)*5
		}
	}
	for _, info := range in.Tools {
		if info != nil {
			n += utf8.RuneCountInString(info.Name) + utf8.RuneCountInString(info.Desc)
		}
	}
	return n, nil
}

func TestModelInputSoftBudgetIncludesSchemaAndOutputWithoutRemovingCapabilities(t *testing.T) {
	mw := &modelInputSoftBudgetMiddleware{
		maxTokens: 220, outputReserveTokens: 70, toolMaxBytes: 12000,
		counter: budgetFixtureCounter, phase: "test",
	}
	scope := schema.SystemMessage("只测staging；禁止改密；保留全部风险族")
	latest := schema.UserMessage("最新要求：双身份A/B，继续验证")
	call := assistantToolCallsMsg("", "call-latest")
	result := schema.ToolMessage("基线与差分证据；gap仍待复核", "call-latest")
	old := schema.AssistantMessage(strings.Repeat("old-completed-work ", 8), nil)
	state := &adk.ChatModelAgentState{Messages: []adk.Message{scope, old, latest, call, result}}
	info := &schema.ToolInfo{Name: "specialist_verify", Desc: strings.Repeat("d", 53)}
	mc := &adk.ModelContext{Tools: []*schema.ToolInfo{info}}
	originalTools := append([]*schema.ToolInfo(nil), mc.Tools...)
	_, out, err := mw.BeforeModelRewriteState(context.Background(), state, mc)
	if err != nil || out == nil {
		t.Fatalf("unexpected budget error: %v", err)
	}
	if out == state {
		t.Fatal("schema/output allowance should trigger history budgeting even when messages alone fit the window")
	}
	if !reflect.DeepEqual(mc.Tools, originalTools) || mc.Tools[0] != info {
		t.Fatal("budgeting must not remove, replace or mutate tool capabilities")
	}
	for _, required := range []adk.Message{scope, latest, call, result} {
		found := false
		for _, msg := range out.Messages {
			if msg == required {
				found = true
			}
		}
		if !found {
			t.Fatalf("lost current constraints, latest user input or paired evidence: %+v", required)
		}
	}
	total, err := countMessagesTokens(context.Background(), out.Messages, mw.counter, mc.Tools)
	if err != nil || total+mw.outputReserveTokens > mw.maxTokens {
		t.Fatalf("actual request estimate + output reserve exceeds window: %d + %d > %d (%v)", total, mw.outputReserveTokens, mw.maxTokens, err)
	}
	if len(state.Messages) != 5 || state.Messages[1] != old {
		t.Fatal("source state must remain intact")
	}
}

func TestModelInputSoftBudgetPreservesContextWhenSchemasConsumeWindow(t *testing.T) {
	mw := &modelInputSoftBudgetMiddleware{maxTokens: 10, outputReserveTokens: 8, counter: budgetFixtureCounter}
	state := &adk.ChatModelAgentState{Messages: []adk.Message{schema.SystemMessage("范围与覆盖门禁"), schema.UserMessage("当前任务")}}
	mc := &adk.ModelContext{Tools: []*schema.ToolInfo{{Name: "tool", Desc: "完整schema仍需保留"}}}
	_, out, err := mw.BeforeModelRewriteState(context.Background(), state, mc)
	if err != nil || out != state || len(mc.Tools) != 1 {
		t.Fatal("an impossible budget must pass intact context to overflow recovery, not silently drop capabilities")
	}
}

func TestModelInputSoftBudgetCounterErrorDoesNotDiscardContext(t *testing.T) {
	mw := &modelInputSoftBudgetMiddleware{
		maxTokens: 100,
		counter: func(context.Context, *summarization.TokenCounterInput) (int, error) {
			return 0, errors.New("fixture counting unavailable")
		},
	}
	state := &adk.ChatModelAgentState{Messages: []adk.Message{schema.UserMessage("完整原始约束")}}
	_, out, err := mw.BeforeModelRewriteState(context.Background(), state, nil)
	if err != nil || out != state {
		t.Fatal("counting failure must not rewrite the task")
	}
}

func TestModelInputSoftBudgetReserveDefaultsAndTailWiring(t *testing.T) {
	mw := newModelInputSoftBudgetMiddleware(1000, 12000, "gpt-4o", nil, "test").(*modelInputSoftBudgetMiddleware)
	if mw.outputReserveTokens != 0 {
		t.Fatal("omitted reserve must preserve existing constructor behavior")
	}
	handlers := appendEinoChatModelTailMiddlewares(nil, einoChatModelTailConfig{
		maxTotalTokens: 1000, outputReserveTokens: 200,
		skipTelemetry: true, skipTrace: true,
	})
	found := false
	for _, handler := range handlers {
		if budget, ok := handler.(*modelInputSoftBudgetMiddleware); ok {
			found = true
			if budget.maxTokens != 1000 || budget.outputReserveTokens != 200 {
				t.Fatal("tail middleware did not propagate the model output allowance")
			}
		}
	}
	if !found {
		t.Fatal("missing final request budget middleware")
	}
}
