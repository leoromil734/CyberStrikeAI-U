package multiagent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/projectprompt"

	"github.com/cloudwego/eino/components/tool"
)

// This reproduces c0bb176's discovery rules and duplicate shared Shell block
// solely as a fixed token fixture. It is not used by any runtime prompt.
const preOptimizationToolDiscoveryIntro = "说明：若启用了 tool_search，则列表里可能含「非常驻」工具——它们不一定出现在当前轮次下发给模型的工具定义中；在未看到该工具的完整 schema 前，禁止凭名称臆测参数。\n"

const preOptimizationToolDiscoveryRules = `
使用规则：
1) 上表仅为名称索引，不含参数定义。禁止猜测参数名、类型、枚举取值或是否必填。
【强制 / 最高优先级】本会话已启用 tool_search（动态工具池）。凡名称索引里出现、但你在「当前请求所附 tools 定义」中看不到其完整参数 schema 的工具，一律必须先调用 tool_search；为省 token 或赶进度而跳过 tool_search、直接调用业务工具，属于明确禁止的错误流程。
2) 默认策略：只要对目标工具的参数定义有任何不确定，就先 tool_search；宁可多一次 tool_search，也不要在未见 schema 时盲调业务工具。
3) 调用顺序：先 tool_search（唯一必填参数 regex_pattern：按工具名匹配的正则，如子串 nuclei 或 ^exact_tool_name$）→ 在后续轮次确认目标工具已出现在 tools 列表且已阅读其 schema → 再发起对该工具的真实调用。
4) tool_search 的返回仅为匹配到的工具名列表；schema 在解锁后的下一轮才会下发。禁止在 schema 未出现时编造 JSON 参数。
5) 不要臆造不存在的工具名。

`

func TestContextTokenOptimizationToolPromptFixture(t *testing.T) {
	ctx := context.Background()
	tools := []tool.BaseTool{stubTool{name: "exec"}}
	for i := 0; i < 60; i++ {
		tools = append(tools, stubTool{name: fmt.Sprintf("fixture__specialist_tool_%02d", i)})
	}
	instruction := projectprompt.ComposeSystemPrompt("角色独有职责：保留范围、全部风险方向与证据状态。", projectprompt.PromptModeDeep)
	var original strings.Builder
	original.WriteString("以下是当前会话绑定的工具名称索引（仅名称，无参数 JSON Schema）。\n")
	original.WriteString(preOptimizationToolDiscoveryIntro)
	for _, name := range collectToolNames(ctx, tools) {
		original.WriteString("- " + name + "\n")
	}
	original.WriteString(preOptimizationToolDiscoveryRules)
	original.WriteString(projectprompt.ShellExecExecuteGuidanceSection() + "\n\n")
	original.WriteString(instruction)
	optimized := injectToolNamesOnlyInstruction(ctx, instruction, tools, true)
	tc := agent.NewTikTokenCounter()
	before, err := tc.Count("gpt-4o", original.String())
	if err != nil {
		t.Fatal(err)
	}
	after, err := tc.Count("gpt-4o", optimized)
	if err != nil {
		t.Fatal(err)
	}
	if after >= before || !strings.Contains(optimized, instruction) {
		t.Fatalf("prompt fixture must shrink while retaining the full contract: %d -> %d", before, after)
	}
	for _, name := range collectToolNames(ctx, tools) {
		if !strings.Contains(optimized, "- "+name+"\n") {
			t.Fatalf("lost callable tool name %s", name)
		}
	}
	t.Logf("full system/tool-index fixture (gpt-4o tokenizer): before=%d after=%d saved=%.1f%%; all %d names and full shared contract preserved", before, after, 100*float64(before-after)/float64(before), len(tools))
}

func TestContextTokenOptimizationSkillEntriesFixture(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate fixture sources")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "skills"))
	tc := agent.NewTikTokenCounter()
	for _, name := range []string{"specialized-attack-playbooks", "cdn-tls-fingerprint"} {
		t.Run(name, func(t *testing.T) {
			original, err := os.ReadFile(filepath.Join(root, name, "references", "original-skill.md"))
			if err != nil {
				t.Fatal(err)
			}
			entry, err := os.ReadFile(filepath.Join(root, name, "SKILL.md"))
			if err != nil {
				t.Fatal(err)
			}
			before, err := tc.Count("gpt-4o", string(original))
			if err != nil {
				t.Fatal(err)
			}
			after, err := tc.Count("gpt-4o", string(entry))
			if err != nil {
				t.Fatal(err)
			}
			if after >= before {
				t.Fatalf("first-load skill text must be smaller: %d -> %d", before, after)
			}
			t.Logf("%s complete entry text fixture (gpt-4o tokenizer): before=%d after=%d saved=%.1f%%; original text remains in the verified archive", name, before, after, 100*float64(before-after)/float64(before))
			if name == "specialized-attack-playbooks" {
				// Include the largest standalone topic, rather than measuring only
				// a thin index and pretending that the actual details are free.
				topic, err := os.ReadFile(filepath.Join(root, name, "references", "ocs-minio.md"))
				if err != nil {
					t.Fatal(err)
				}
				withTopic, err := tc.Count("gpt-4o", string(entry)+"\n\n"+string(topic))
				if err != nil {
					t.Fatal(err)
				}
				if withTopic >= before {
					t.Fatal("index plus selected full topic should still be smaller than the all-inline entry")
				}
				t.Logf("%s entry + largest single full topic fixture: before=%d after=%d saved=%.1f%%", name, before, withTopic, 100*float64(before-withTopic)/float64(before))
			}
		})
	}
}
