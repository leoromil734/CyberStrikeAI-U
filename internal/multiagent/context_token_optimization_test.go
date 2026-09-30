package multiagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/projectprompt"

	"github.com/cloudwego/eino/components/tool"
)

func decodeCompactUserContext(t *testing.T, text string) []string {
	t.Helper()
	if !strings.HasPrefix(text, losslessUserContextNote) {
		t.Fatalf("expected lossless encoding, got %q", text)
	}
	var encoded losslessUserContext
	if err := json.Unmarshal([]byte(strings.TrimPrefix(text, losslessUserContextNote)), &encoded); err != nil {
		t.Fatal(err)
	}
	prefixes := make(map[int]string)
	for _, prefix := range encoded.Prefixes {
		if _, exists := prefixes[prefix.ID]; exists || prefix.ID <= 0 {
			t.Fatalf("invalid prefix id %d", prefix.ID)
		}
		prefixes[prefix.ID] = prefix.Text
	}
	messages := make([]string, 0, len(encoded.Turns))
	for i, turn := range encoded.Turns {
		if turn.Turn != i+1 {
			t.Fatalf("turn chronology changed: %+v", turn)
		}
		if turn.Ref != 0 {
			if turn.Ref < 1 || turn.Ref >= turn.Turn || turn.Prefix != 0 || turn.Text != "" {
				t.Fatalf("invalid/backward-incompatible reference: %+v", turn)
			}
			messages = append(messages, messages[turn.Ref-1])
			continue
		}
		prefix := ""
		if turn.Prefix != 0 {
			var exists bool
			prefix, exists = prefixes[turn.Prefix]
			if !exists {
				t.Fatalf("missing prefix %d", turn.Prefix)
			}
		}
		messages = append(messages, prefix+turn.Text)
	}
	return messages
}

func TestLosslessUserContextPreservesEveryTurnAndPayload(t *testing.T) {
	prefix := strings.Repeat("范围与证据要求：保留全部风险方向；未测不算排除。\n", 18)
	a := prefix + "\n\n只测 staging，不测 production。\nPOST /api/orders\n{\"path\":\"A  B\",\"payload\":\"<x>\\n\"}"
	b := prefix + "\n\n最新修改：同时评估 tenant-b；禁止改密。\nAuthorization: fixture-token"
	messages := []string{a, b, a, prefix + "\n\n最后要求：按最新范围继续；不要删除中间身份约束。"}
	compact := compactUserContextTurns(messages, []string{prefix})
	decoded := decodeCompactUserContext(t, compact)
	if len(decoded) != len(messages) {
		t.Fatalf("lost turns: got %d, want %d", len(decoded), len(messages))
	}
	for i := range messages {
		if decoded[i] != messages[i] {
			t.Fatalf("turn %d changed bytes\n got: %q\nwant: %q", i+1, decoded[i], messages[i])
		}
	}
}

func TestLosslessUserContextNeverSummarizesUniqueInputs(t *testing.T) {
	messages := []string{"范围：example.test", "禁测 /payments", "改为 tenant-b", "新增风险族：XML与WebSocket", "以最新要求为准"}
	if got := compactUserContextTurns(messages, nil); got != renderVerbatimUserContextTurns(messages) {
		t.Fatalf("unique inputs must remain verbatim: %q", got)
	}
}

func TestLosslessUserContextKeepsInvalidUTF8Verbatim(t *testing.T) {
	payload := strings.Repeat("original-data ", 80) + string([]byte{0xff, 0xfe})
	messages := []string{payload, payload}
	if got := compactUserContextTurns(messages, nil); got != renderVerbatimUserContextTurns(messages) {
		t.Fatal("JSON replacement characters must never alter historical bytes")
	}
}

func TestLosslessUserContextPreservesNonAdjacentRepetition(t *testing.T) {
	a := strings.Repeat("A原始范围与凭据，保持空格  与换行。\n", 30)
	b := strings.Repeat("B新身份与新范围，不能丢失本轮变更。\n", 30)
	messages := []string{a, b, a, b, a}
	decoded := decodeCompactUserContext(t, compactUserContextTurns(messages, nil))
	for i := range messages {
		if decoded[i] != messages[i] {
			t.Fatalf("A->B->A precedence/chronology lost at turn %d", i+1)
		}
	}
}

func TestLosslessUserContextDeterministicWithOverlappingRolePrefixes(t *testing.T) {
	short := strings.Repeat("角色规则。", 40)
	long := short + "\n\n" + strings.Repeat("额外共享规则。", 40)
	messages := []string{long + "\n\n目标A", long + "\n\n目标B", short + "\n\n目标C", short + "\n\n目标D"}
	left := compactUserContextTurns(messages, []string{short, long, short})
	right := compactUserContextTurns(messages, []string{long, short})
	if left != right {
		t.Fatal("map/configuration order must not change encoding")
	}
	decoded := decodeCompactUserContext(t, left)
	for i := range messages {
		if decoded[i] != messages[i] {
			t.Fatalf("overlapping prefix changed turn %d", i+1)
		}
	}
}

func TestTaskContextEnrichmentIsIdempotentAndKeepsBlackboard(t *testing.T) {
	blackboard := "<project-fact-index>phase=active; gap=object-authorization; identity=A/B</project-fact-index>"
	mw := newTaskContextEnrichMiddleware("最新约束：不要改密", []agent.ChatMessage{{Role: "user", Content: "完整范围：example.test"}}, 0, blackboard).(*taskContextEnrichMiddleware)
	first := mw.enrichTaskDescription(`{"subagent_type":"penetration","description":"验证一个候选"}`)
	if second := mw.enrichTaskDescription(first); second != first {
		t.Fatal("retry must not append the same full user/blackboard block again")
	}
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(first), &args); err != nil {
		t.Fatal(err)
	}
	description := args["description"].(string)
	for _, required := range []string{"验证一个候选", "完整范围：example.test", "不要改密", blackboard} {
		if !strings.Contains(description, required) {
			t.Fatalf("required context missing: %q", required)
		}
	}
}

func TestTaskContextLosslessCompressionFitsCapBeforeLegacyTruncation(t *testing.T) {
	prompt := strings.Repeat("每个风险单元必须记录证据。", 100)
	history := []agent.ChatMessage{{Role: "user", Content: prompt + "\n\n第一轮范围"}, {Role: "user", Content: prompt + "\n\n中间约束：tenant-b不能写入"}}
	full := buildUserContextSupplement(prompt+"\n\n最后要求", history, 0, prompt)
	cap := utf8RuneLen(strings.TrimPrefix(full, userContextSupplementHeader))
	bounded := buildUserContextSupplement(prompt+"\n\n最后要求", history, cap, prompt)
	if full != bounded || !strings.Contains(bounded, "中间约束：tenant-b不能写入") {
		t.Fatal("lossless factoring should preserve middle constraints when it fits the explicit cap")
	}
}

func TestConfiguredRolePromptsKeepDisabledHistoricalTemplates(t *testing.T) {
	cfg := &config.Config{Roles: map[string]config.RoleConfig{
		"old": {UserPrompt: " old-role ", Enabled: false},
		"new": {UserPrompt: "new-role", Enabled: true},
	}}
	prompts := configuredRoleUserPrompts(cfg)
	if len(prompts) != 2 {
		t.Fatalf("historical templates must remain available for byte factoring: %v", prompts)
	}
}

func TestToolIndexOptimizationPreservesAllNamesAndSharedContract(t *testing.T) {
	tools := []tool.BaseTool{stubTool{name: "exec"}, stubTool{name: "http-framework-test"}, stubTool{name: "recon__collect"}, stubTool{name: "custom__verify"}}
	instruction := projectprompt.ComposeSystemPrompt("ROLE_UNIQUE_MARKER", projectprompt.PromptModeDeep)
	got := injectToolNamesOnlyInstruction(context.Background(), instruction, tools, true)
	if !strings.Contains(got, instruction) {
		t.Fatal("full shared/role contract must remain unchanged")
	}
	for _, name := range collectToolNames(context.Background(), tools) {
		if !strings.Contains(got, "- "+name+"\n") {
			t.Fatalf("tool direction/name disappeared: %s", name)
		}
	}
	if count := strings.Count(got, projectprompt.ShellExecExecuteGuidanceSection()); count != 1 {
		t.Fatalf("shared Shell guidance count=%d, want 1", count)
	}
	for _, rule := range []string{"禁止猜测参数", "臆造工具名", "一律必须先调用 tool_search", "regex_pattern", "schema 在下一轮下发", "未出现前禁止调用", "不得为省 token"} {
		if !strings.Contains(got, rule) {
			t.Fatalf("schema/search safety requirement missing: %q", rule)
		}
	}
}

func TestContextTokenOptimizationFixture(t *testing.T) {
	tc := agent.NewTikTokenCounter()
	prefix := strings.Repeat("角色规则：保留全部授权范围与风险方向，验证后记录完整证据；不得提前收尾。\n", 25)
	messages := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		messages = append(messages, prefix+fmt.Sprintf("\n\n第%d轮：example.test/tenant-%d；保留各自身份和参数。", i+1, i))
	}
	before, err := tc.Count("gpt-4o", renderVerbatimUserContextTurns(messages))
	if err != nil {
		t.Fatal(err)
	}
	after, err := tc.Count("gpt-4o", compactUserContextTurns(messages, []string{prefix}))
	if err != nil {
		t.Fatal(err)
	}
	if after >= before {
		t.Fatalf("lossless fixture failed to reduce tokens: before=%d after=%d", before, after)
	}
	t.Logf("lossless role/history fixture (gpt-4o tokenizer): before=%d after=%d saved=%.1f%%; all %d turns restored byte-for-byte", before, after, 100*float64(before-after)/float64(before), len(messages))
	decoded := decodeCompactUserContext(t, compactUserContextTurns(messages, []string{prefix}))
	for i := range messages {
		if decoded[i] != messages[i] {
			t.Fatalf("fixture data changed at turn %d", i+1)
		}
	}
}
