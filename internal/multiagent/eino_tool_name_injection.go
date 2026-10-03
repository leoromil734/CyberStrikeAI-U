package multiagent

import (
	"context"
	"strings"

	"github.com/cloudwego/eino/components/tool"
)

// injectToolNamesOnlyInstruction prepends a compact tool-name-only section into
// the system instruction so the model can reference current callable names.
// toolSearchMiddlewareActive must be true when prependEinoMiddlewares mounted toolsearch (dynamic tools); do not infer this
// by scanning tool names — tool_search is injected by middleware and is usually absent from the pre-split tools list.
func injectToolNamesOnlyInstruction(ctx context.Context, instruction string, tools []tool.BaseTool, toolSearchMiddlewareActive bool) string {
	names := collectToolNames(ctx, tools)
	if len(names) == 0 {
		return strings.TrimSpace(instruction)
	}
	hasToolSearch := toolSearchMiddlewareActive
	if !hasToolSearch {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSpace(n), "tool_search") {
				hasToolSearch = true
				break
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("以下是当前会话绑定的工具名称索引（仅名称，无参数 JSON Schema）。\n")
	for _, name := range names {
		sb.WriteString("- ")
		sb.WriteString(name)
		sb.WriteByte('\n')
	}
	sb.WriteString("\n使用规则：名称索引不等于当前可调用 schema；参数名、类型、枚举与必填项仅以当前请求 tools 定义为准，禁止猜测参数或臆造工具名。\n")
	if hasToolSearch {
		sb.WriteString("【强制】已启用 tool_search：当前 tools 尚无完整 schema 的非常驻工具，一律必须先调用 tool_search；不得为省 token 或赶进度跳过。\n")
		sb.WriteString("tool_search 仅搜索非常驻工具；空结果不代表常驻工具不可用。当前 tools 已有完整 schema 的工具直接按该定义调用，无需重复搜索；索引与 schema 均缺失才记录当前角色工具缺口，不得绕过白名单或编造调用。\n")
		sb.WriteString("非常驻工具的加载顺序：tool_search（唯一必填 regex_pattern：工具名正则，如 nuclei 或 ^exact_tool_name$）→ 后续轮次看到并读完目标 schema → 调用业务工具。搜索返回仅工具名，schema 在下一轮下发，未出现前禁止调用。\n\n")
	} else {
		sb.WriteString("调用前确认当前 tools 中的完整参数要求；不确定时先澄清再调用。\n\n")
	}
	if s := strings.TrimSpace(injectShellToolGuidance(instruction, names)); s != "" {
		sb.WriteString(s)
	}
	return sb.String()
}

func collectToolNames(ctx context.Context, tools []tool.BaseTool) []string {
	if len(tools) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tools))
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		info, err := t.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		name := strings.TrimSpace(info.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	return out
}
