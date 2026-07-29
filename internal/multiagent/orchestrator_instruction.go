package multiagent

import (
	"strings"

	"cyberstrike-ai/internal/agents"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/projectprompt"
)

const defaultDeepOrchestratorRoleInstruction = `你是 CyberStrikeAI 的 Deep 协调主代理。你负责维护全局目标与证据状态，把适合隔离上下文的专项工作交给子代理，并对最终结论负责。

## Deep 协调职责

- 先识别当前证据缺口，再决定委派或亲自执行；不要为了使用 task 而拆分轻量工作。
- 委派侦察、分诊、验证和报告等专项子目标时，选择职责匹配的代理，禁止让验证角色重新做全量侦察。
- 子代理只提供局部证据；你负责去重、解决矛盾、补齐独立安全边界，并把正负结果合并到全局状态。
- 超过两个相互依赖的子目标时维护简短待办；同一时刻只推进一个有依赖的主路径，无依赖且范围清晰的任务可并行。`

const defaultSupervisorRoleInstruction = `你是 CyberStrikeAI 的 Supervisor 专家路由协调者。你负责在多个专业子代理之间选择最短有效路径，校验专家证据，并通过 exit 交付统一结论。

## Supervisor 协调职责

- transfer 只用于确有专业分流收益的子目标；简单查询、单步工具调用和全局衔接由你直接完成。
- 不在同一专家之间反复转派；只有出现新的具体目标、证据矛盾或验证缺口时才追加 transfer。
- 每次 transfer 前确认目标标识与 in-scope 边界完整；缺失时先补全，不让专家猜测目标。
- 专家返回后裁剪噪声、对齐基线与攻击证据；达到完成条件后用 exit 交付，不机械拼接专家原文。`

const defaultPlanExecuteRoleInstruction = `你是 CyberStrikeAI 的 Plan-Execute 规划主代理。你负责制定可执行计划、根据执行证据重规划，并驱动执行器使用 MCP 工具落地；你不使用 Deep 的 task 子代理。

## Planner 职责

- 计划只保留当前目标所需步骤，明确依赖和顺序，避免“全面检查”“深入分析”等不可验收动词。
- 每轮执行后把步骤状态更新为继续、调整、缩小范围或终止；失败步骤必须带原因和替代路径，禁止原样重试。
- 验证步骤要求执行器给出基线/攻击对照与原始证据；记录步骤区分 tentative fact 和 confirmed vulnerability。
- 执行器面向用户的正文必须是自然语言，不使用 {"response":"..."} 等 JSON 包裹。`

// DefaultPlanExecuteOrchestratorInstruction 返回 Plan-Execute 内置角色提示与共享运行契约。
func DefaultPlanExecuteOrchestratorInstruction() string {
	return projectprompt.ComposeSystemPrompt(defaultPlanExecuteRoleInstruction, projectprompt.PromptModePlanExecute)
}

// DefaultSupervisorOrchestratorInstruction 返回 Supervisor 内置角色提示与共享运行契约。
func DefaultSupervisorOrchestratorInstruction() string {
	return projectprompt.ComposeSystemPrompt(defaultSupervisorRoleInstruction, projectprompt.PromptModeSupervisor)
}

// DefaultDeepOrchestratorInstruction 返回 Deep 内置角色提示与共享运行契约。
func DefaultDeepOrchestratorInstruction() string {
	return projectprompt.ComposeSystemPrompt(defaultDeepOrchestratorRoleInstruction, projectprompt.PromptModeDeep)
}

// resolveMainOrchestratorInstruction 按编排模式选择角色提示，再统一追加共享运行契约。
// plan_execute / supervisor 不回退到 Deep 配置，避免混用生命周期。
func resolveMainOrchestratorInstruction(mode string, ma *config.MultiAgentConfig, markdownLoad *agents.MarkdownDirLoad) (instruction string, meta *agents.OrchestratorMarkdown) {
	if ma == nil {
		return "", nil
	}

	var roleInstruction string
	var promptMode projectprompt.PromptMode

	switch mode {
	case "plan_execute":
		promptMode = projectprompt.PromptModePlanExecute
		if markdownLoad != nil {
			meta = markdownLoad.OrchestratorPlanExecute
			if meta != nil {
				roleInstruction = strings.TrimSpace(meta.Instruction)
			}
		}
		if roleInstruction == "" {
			roleInstruction = strings.TrimSpace(ma.OrchestratorInstructionPlanExecute)
		}
		if roleInstruction == "" {
			roleInstruction = defaultPlanExecuteRoleInstruction
		}
	case "supervisor":
		promptMode = projectprompt.PromptModeSupervisor
		if markdownLoad != nil {
			meta = markdownLoad.OrchestratorSupervisor
			if meta != nil {
				roleInstruction = strings.TrimSpace(meta.Instruction)
			}
		}
		if roleInstruction == "" {
			roleInstruction = strings.TrimSpace(ma.OrchestratorInstructionSupervisor)
		}
		if roleInstruction == "" {
			roleInstruction = defaultSupervisorRoleInstruction
		}
	default:
		promptMode = projectprompt.PromptModeDeep
		if markdownLoad != nil {
			meta = markdownLoad.Orchestrator
			if meta != nil {
				roleInstruction = strings.TrimSpace(meta.Instruction)
			}
		}
		if roleInstruction == "" {
			roleInstruction = strings.TrimSpace(ma.OrchestratorInstruction)
		}
		if roleInstruction == "" {
			roleInstruction = defaultDeepOrchestratorRoleInstruction
		}
	}

	return projectprompt.ComposeSystemPrompt(roleInstruction, promptMode), meta
}
