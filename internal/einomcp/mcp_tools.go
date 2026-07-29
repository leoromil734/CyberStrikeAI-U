package einomcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/security"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
)

// ExecutionRecorder 可选，在 MCP 工具成功返回且带有 execution id 时回调（用于汇总 mcpExecutionIds）。
// toolCallID 来自 Eino compose.GetToolCallID，用于与 reduction 后的展示结果关联。
type ExecutionRecorder func(executionID, toolCallID string)

// ToolErrorPrefix 用于把内部 MCP 执行结果中的 IsError 标记传递到多代理上层。
// Eino 工具通道目前只支持返回字符串，因此通过前缀标识，随后在多代理 runner 中解析为 success/isError。
const ToolErrorPrefix = "__CYBERSTRIKE_AI_TOOL_ERROR__\n"

// ToolsFromDefinitions 将单 Agent 使用的 OpenAI 风格工具定义转为 Eino InvokableTool，执行时走 Agent 的 MCP 路径。
// invokeNotify 可选：与 runEinoADKAgentLoop 共享，在 InvokableRun 返回时触发 UI 与 pending 清理（与 ADK Tool 事件去重）。
// einoAgentName 为该套工具所属 ChatModelAgent 的 Name（主代理或子代理 id），用于 SSE 上的 einoAgent 字段。
func ToolsFromDefinitions(
	ag *agent.Agent,
	holder *ConversationHolder,
	defs []agent.Tool,
	rec ExecutionRecorder,
	toolOutputChunk func(toolName, toolCallID, chunk string),
	invokeNotify *ToolInvokeNotifyHolder,
	einoAgentName string,
) ([]tool.BaseTool, error) {
	out := make([]tool.BaseTool, 0, len(defs))
	modelNames := make(map[string]string, len(defs))
	for _, d := range defs {
		if d.Type != "function" || d.Function.Name == "" {
			continue
		}
		canonicalName := strings.TrimSpace(d.Function.Name)
		modelName := normalizeEinoToolName(canonicalName)
		if existing, ok := modelNames[modelName]; ok && existing != canonicalName {
			return nil, fmt.Errorf("tool name collision after Eino normalization: %q and %q -> %q", existing, canonicalName, modelName)
		}
		modelNames[modelName] = canonicalName
		d.Function.Name = modelName
		info, err := toolInfoFromDefinition(d)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", canonicalName, err)
		}
		out = append(out, &mcpBridgeTool{
			info:          info,
			name:          canonicalName,
			modelName:     modelName,
			agent:         ag,
			holder:        holder,
			record:        rec,
			chunk:         toolOutputChunk,
			invokeNotify:  invokeNotify,
			einoAgentName: strings.TrimSpace(einoAgentName),
		})
	}
	return out, nil
}

func normalizeEinoToolName(name string) string {
	return strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
}

func toolInfoFromDefinition(d agent.Tool) (*schema.ToolInfo, error) {
	fn := d.Function
	raw, err := json.Marshal(fn.Parameters)
	if err != nil {
		return nil, err
	}
	var js jsonschema.Schema
	if len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
		if err := json.Unmarshal(raw, &js); err != nil {
			return nil, err
		}
	}
	if js.Type == "" {
		js.Type = string(schema.Object)
	}
	if js.Properties == nil && js.Type == string(schema.Object) {
		// 空参数对象
	}
	return &schema.ToolInfo{
		Name:        fn.Name,
		Desc:        fn.Description,
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(&js),
	}, nil
}

type mcpBridgeTool struct {
	info          *schema.ToolInfo
	name          string // MCP 规范名
	modelName     string // 暴露给 Eino/模型的规范化名称
	agent         *agent.Agent
	holder        *ConversationHolder
	record        ExecutionRecorder
	chunk         func(toolName, toolCallID, chunk string)
	invokeNotify  *ToolInvokeNotifyHolder
	einoAgentName string

	recoveryMu     sync.Mutex
	execRecoveries map[string]execRecoveryState
}

type execRecoveryState struct {
	lastCommand string
	kind        string
	attempts    int
}

const maxExecSyntaxRepairAttempts = 1

func (m *mcpBridgeTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	_ = ctx
	return m.info, nil
}

func (m *mcpBridgeTool) InvokableRun(ctx context.Context, argumentsInJSON string, opts ...tool.Option) (out string, err error) {
	_ = opts
	toolCallID := compose.GetToolCallID(ctx)
	defer func() {
		if m.invokeNotify == nil {
			return
		}
		tid := strings.TrimSpace(toolCallID)
		if tid == "" {
			return
		}
		success := err == nil && !strings.HasPrefix(out, ToolErrorPrefix)
		body := out
		if err != nil {
			success = false
		} else if strings.HasPrefix(out, ToolErrorPrefix) {
			success = false
			body = strings.TrimPrefix(out, ToolErrorPrefix)
		}
		notifyName := strings.TrimSpace(m.modelName)
		if notifyName == "" {
			notifyName = m.name
		}
		m.invokeNotify.Fire(tid, notifyName, m.einoAgentName, success, body, err)
	}()
	out, err = runMCPToolInvocation(ctx, m.agent, m.holder, m.name, argumentsInJSON, m.record, m.chunk)
	out = m.decorateExecSyntaxFailure(argumentsInJSON, out, err)
	return out, err
}

func (m *mcpBridgeTool) decorateExecSyntaxFailure(argumentsInJSON, out string, invokeErr error) string {
	if m == nil || !strings.EqualFold(strings.TrimSpace(m.name), "exec") || invokeErr != nil {
		return out
	}

	conversationID := ""
	if m.holder != nil {
		conversationID = strings.TrimSpace(m.holder.Get())
	}
	if conversationID == "" {
		conversationID = "_default"
	}

	body, isToolError := strings.CutPrefix(out, ToolErrorPrefix)
	if !isToolError {
		m.clearExecRecovery(conversationID)
		return out
	}

	command := execCommandFromArguments(argumentsInJSON)
	recoveryKind := ""
	switch {
	case isRepairableExecSyntaxFailure(body):
		recoveryKind = "syntax"
	case isRepairableExecHTTPParseFailure(command, body):
		recoveryKind = "http_response_parse"
	default:
		m.clearExecRecovery(conversationID)
		return out
	}

	m.recoveryMu.Lock()
	if m.execRecoveries == nil {
		m.execRecoveries = make(map[string]execRecoveryState)
	}
	state := m.execRecoveries[conversationID]
	if state.kind != "" && state.kind != recoveryKind {
		state = execRecoveryState{}
	}
	if state.attempts >= maxExecSyntaxRepairAttempts {
		unchanged := command != "" && command == state.lastCommand
		m.recoveryMu.Unlock()
		if recoveryKind == "http_response_parse" {
			return ToolErrorPrefix + body + execHTTPParseRecoveryExhaustedMessage(unchanged)
		}
		return ToolErrorPrefix + body + execSyntaxRepairExhaustedMessage(unchanged)
	}
	state.attempts++
	state.lastCommand = command
	state.kind = recoveryKind
	m.execRecoveries[conversationID] = state
	m.recoveryMu.Unlock()

	if recoveryKind == "http_response_parse" {
		return ToolErrorPrefix + body + execHTTPParseRecoveryInstruction(state.attempts)
	}
	return ToolErrorPrefix + body + execSyntaxRepairInstruction(state.attempts)
}

func (m *mcpBridgeTool) clearExecRecovery(conversationID string) {
	m.recoveryMu.Lock()
	defer m.recoveryMu.Unlock()
	delete(m.execRecoveries, conversationID)
}

func execCommandFromArguments(argumentsInJSON string) string {
	var args struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
		return ""
	}
	return strings.TrimSpace(args.Command)
}

func isRepairableExecSyntaxFailure(result string) bool {
	result = strings.ToLower(result)
	markers := []string{
		"syntax error",
		"syntaxerror:",
		"indentationerror:",
		"unexpected token",
		"unexpected eof while looking for matching",
		"unterminated quoted string",
		"unmatched '",
		"bad substitution",
	}
	for _, marker := range markers {
		if strings.Contains(result, marker) {
			return true
		}
	}
	return false
}

func isRepairableExecHTTPParseFailure(command, result string) bool {
	command = strings.ToLower(command)
	result = strings.ToLower(result)
	if !strings.Contains(command, "curl") ||
		(!strings.Contains(command, "json.load") && !strings.Contains(command, "json.loads")) {
		return false
	}
	markers := []string{
		"jsondecodeerror",
		"expecting value: line 1 column 1",
		"unexpected end of json input",
		"unexpected eof",
	}
	for _, marker := range markers {
		if strings.Contains(result, marker) {
			return true
		}
	}
	// stderr 被主动丢弃时，非零退出且没有诊断文本也属于同一可恢复模式。
	return strings.Contains(command, "2>/dev/null") &&
		strings.Contains(result, "命令执行失败") &&
		strings.TrimSpace(result) != ""
}

func execHTTPParseRecoveryInstruction(attempt int) string {
	return fmt.Sprintf(`

[HTTP Response Parse Recovery]
retryable: true
repair_attempt: %d/%d
required_action: Retry once with a diagnostic request before parsing.
constraints:
- Do not suppress stderr and do not pipe curl directly into a JSON parser.
- Capture HTTP status, final URL, Content-Type, response length, and a bounded body preview first.
- Parse JSON only when the body is non-empty and Content-Type/body shape supports JSON.
- Prefer the dedicated http-framework-test tool; if a body file is needed, save it in the session workspace and inspect it with read_file.
- Treat an empty/non-JSON response as target behavior for this request, then switch endpoint, method, headers, or authenticated browser flow instead of repeating the same parser.

[HTTP 响应解析恢复]
当前失败发生在“尚未确认响应就直接按 JSON 解析”。请保留 stderr，先采集状态码、最终 URL、Content-Type、响应长度和有界正文预览；仅在正文非空且确为 JSON 时解析。优先改用 http-framework-test。`, attempt, maxExecSyntaxRepairAttempts)
}

func execHTTPParseRecoveryExhaustedMessage(unchanged bool) string {
	reason := "the diagnostic retry still attempted to parse an empty or non-JSON response"
	if unchanged {
		reason = "the failed HTTP parsing command was repeated unchanged"
	}
	return fmt.Sprintf(`

[HTTP Response Parse Recovery]
retryable: false
repair_attempt: exhausted
reason: %s
required_action: Stop this parser strategy. Preserve the HTTP diagnostic evidence and switch to http-framework-test, a browser-authenticated request, or a different endpoint/method/header baseline. This blocked request does not justify ending the assessment or omitting the final report.

[HTTP 响应解析恢复]
该解析策略已耗尽。保留 HTTP 诊断证据并切换专用 HTTP 工具、浏览器认证态请求或不同入口；单个请求被阻断不等于任务完成，也不能省略最终报告。`, reason)
}

func execSyntaxRepairInstruction(attempt int) string {
	return fmt.Sprintf(`

[Exec Recovery]
retryable: true
repair_attempt: %d/%d
required_action: Inspect the parser error, produce a DIFFERENT corrected command, and call exec exactly once more before continuing.
constraints:
- Never repeat the failed command unchanged.
- Do not nest a multiline Python/JavaScript program inside a shell double-quoted -c argument.
- Prefer a single-quoted heredoc (for example, python3 - <<'PY') or a temporary script file so the shell cannot expand the program body.
- Preserve the original task intent; change only quoting, script transport, shell selection, or syntax needed to execute it.

[exec 智能恢复]
这是可修复的命令语法错误。请检查解析器报错，生成一条不同的修正命令，并且仅重试一次 exec 后再继续。禁止原样重复失败命令；多行 Python/JavaScript 优先使用单引号 heredoc 或临时脚本，避免外层 Shell 提前展开脚本正文。`, attempt, maxExecSyntaxRepairAttempts)
}

func execSyntaxRepairExhaustedMessage(unchanged bool) string {
	reason := "the repaired command still has a syntax error"
	if unchanged {
		reason = "the failed command was repeated unchanged"
	}
	return fmt.Sprintf(`

[Exec Recovery]
retryable: false
repair_attempt: exhausted
reason: %s
required_action: Do not call exec again with the same strategy. Use a different tool/transport, or report the blocking syntax issue with the failed command and parser output.

[exec 智能恢复]
语法修复重试额度已耗尽。不要继续使用同一策略调用 exec；请改用其他工具或脚本传输方式，或者明确报告失败命令及解析器输出。`, reason)
}

// runMCPToolInvocation 与 mcpBridgeTool.InvokableRun 共用。
func runMCPToolInvocation(
	ctx context.Context,
	ag *agent.Agent,
	holder *ConversationHolder,
	toolName string,
	argumentsInJSON string,
	record ExecutionRecorder,
	chunk func(toolName, toolCallID, chunk string),
) (string, error) {
	var args map[string]interface{}
	if argumentsInJSON != "" && argumentsInJSON != "null" {
		if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
			// Return soft error (nil error) so the eino graph continues and the LLM can self-correct,
			// instead of a hard error that terminates the iteration loop.
			return ToolErrorPrefix + fmt.Sprintf(
				"Invalid tool arguments JSON: %s\n\nPlease ensure the arguments are a valid JSON object "+
					"(double-quoted keys, matched braces, no trailing commas) and retry.\n\n"+
					"（工具参数 JSON 解析失败：%s。请确保 arguments 是合法的 JSON 对象并重试。）",
				err.Error(), err.Error()), nil
		}
	}
	if args == nil {
		args = map[string]interface{}{}
	}

	if chunk != nil {
		toolCallID := compose.GetToolCallID(ctx)
		if toolCallID != "" {
			if existing, ok := ctx.Value(security.ToolOutputCallbackCtxKey).(security.ToolOutputCallback); ok && existing != nil {
				ctx = context.WithValue(ctx, security.ToolOutputCallbackCtxKey, security.ToolOutputCallback(func(c string) {
					existing(c)
					if strings.TrimSpace(c) == "" {
						return
					}
					chunk(toolName, toolCallID, c)
				}))
			} else {
				ctx = context.WithValue(ctx, security.ToolOutputCallbackCtxKey, security.ToolOutputCallback(func(c string) {
					if strings.TrimSpace(c) == "" {
						return
					}
					chunk(toolName, toolCallID, c)
				}))
			}
		}
	}

	res, err := ag.ExecuteMCPToolForConversation(ctx, holder.Get(), toolName, args)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", nil
	}
	if res.ExecutionID != "" && record != nil {
		record(res.ExecutionID, compose.GetToolCallID(ctx))
	}
	if res.IsError {
		return ToolErrorPrefix + res.Result, nil
	}
	return res.Result, nil
}

// UnknownToolReminderHandler 供 compose.ToolsNodeConfig.UnknownToolsHandler 使用：
// 模型请求了未注册的工具名时，返回一个「软错误」工具结果（nil error），
// 让模型在同一轮继续自我修正，避免触发 run-loop 级别的 full rerun。
// 不进行名称猜测或映射，避免误执行。
func UnknownToolReminderHandler() func(ctx context.Context, name, input string) (string, error) {
	return func(ctx context.Context, name, input string) (string, error) {
		_ = ctx
		_ = input
		requested := strings.TrimSpace(name)
		// Return a soft tool-result error so the graph keeps running and the LLM
		// can correct tool name/arguments within the same run.
		return ToolErrorPrefix + unknownToolReminderText(requested), nil
	}
}

func unknownToolReminderText(requested string) string {
	if requested == "" {
		requested = "(empty)"
	}
	return fmt.Sprintf(`The tool name %q is not registered for this agent.

Please retry using only names that appear in the tool definitions for this turn (exact match, case-sensitive). Do not invent or rename tools; adjust your plan and continue.

（工具 %q 未注册：请仅使用本回合上下文中给出的工具名称，须完全一致；请勿自行改写或猜测名称，并继续后续步骤。）`, requested, requested)
}
