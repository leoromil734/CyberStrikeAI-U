package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/tooloutput"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	finalizationAutoContinueMaxAttempts = 2
	finalizationCoverageMaxAttempts     = 8
	finalizationCoverageNoProgressLimit = 2
	finalizationCoverageRepairTimeout   = 15 * time.Minute
	finalizationPendingWaitTimeout      = 20 * time.Minute
	finalizationPendingPollInterval     = 5 * time.Second
)

// A bounded continuation budget belongs to this request, not to a model response.
// New fact rows or a shorter error list are not evidence progress. Only new,
// independently recorded evidence executions can renew the stagnation allowance.
type finalizationContinuationState struct {
	Attempts                    int
	CoverageObserved            bool
	CoverageValidFactsHighWater int
	CoverageEvidenceHighWater   int
	CoverageNoProgress          int
	StopReason                  string
	StopStatus                  string
}

func finalizationContinuationLimit(d agentfinalizer.Decision) int {
	if d.CompletionReason == agentfinalizer.ReasonCoverageIncomplete {
		return finalizationCoverageMaxAttempts
	}
	return finalizationAutoContinueMaxAttempts
}

func shouldAutoContinueAfterFinalization(d agentfinalizer.Decision, attempt int) bool {
	if d.Finalizable || d.Finalized || attempt >= finalizationContinuationLimit(d) {
		return false
	}
	if d.Status == agentfinalizer.StatusFailed || d.Status == agentfinalizer.StatusCancelled || d.Status == agentfinalizer.StatusAwaitingHITL {
		return false
	}
	switch d.CompletionReason {
	case agentfinalizer.ReasonMissingEvidence, agentfinalizer.ReasonCoverageIncomplete,
		agentfinalizer.ReasonPendingTools, agentfinalizer.ReasonIncompleteCandidate:
		return true
	default:
		return false
	}
}

// observeFinalizationContinuation is separate from trace restoration for tests.
// Attempts are incremented only once a usable trace has actually been restored.
func observeFinalizationContinuation(d agentfinalizer.Decision, state *finalizationContinuationState) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	if !shouldAutoContinueAfterFinalization(d, state.Attempts) {
		if state.Attempts >= finalizationContinuationLimit(d) {
			state.StopReason = fmt.Sprintf("自动续跑已达到本次运行的 %d 段硬上限，检查仍未通过；保留轨迹供人工修复后恢复", finalizationContinuationLimit(d))
		}
		return false
	}
	if d.CompletionReason == agentfinalizer.ReasonCoverageIncomplete {
		if d.CoverageRepairBlocked {
			if !d.CoverageProgressKnown {
				state.StopReason = "独立库存或执行证据状态无法完整核实，已停止自动补写；保留原始缺口，不把读取失败或候选清单当作已覆盖"
			} else {
				state.StopReason = fmt.Sprintf("独立库存仍有 %d 组未处置候选，已停止自动逐条补写；保留全部原件，先按范围、当前性与业务功能分类，未测项不能写成 N/A 或安全", d.CoverageUnresolvedGroups)
			}
			return false
		}
		if state.CoverageObserved {
			if d.CoverageProgressKnown && d.CoverageEvidenceExecutions > state.CoverageEvidenceHighWater {
				state.CoverageNoProgress = 0
			} else {
				state.CoverageNoProgress++
			}
		}
		state.CoverageObserved = true
		if d.CoverageProgressKnown && d.CoverageEvidenceExecutions > state.CoverageEvidenceHighWater {
			state.CoverageEvidenceHighWater = d.CoverageEvidenceExecutions
		}
		if d.CoverageValidFacts > state.CoverageValidFactsHighWater {
			state.CoverageValidFactsHighWater = d.CoverageValidFacts
		}
		if state.CoverageNoProgress >= finalizationCoverageNoProgressLimit {
			state.StopReason = fmt.Sprintf("连续 %d 段续跑未增加独立执行证据，已停止自动补写；新增或改写 fact 不视为测试进展，原件与未完成范围已保留", finalizationCoverageNoProgressLimit)
			return false
		}
	}
	return true
}

// An execution loop ending is not a successful completion. Preserve failed,
// cancelled and approval states, but never leave a stopped run in_progress.
func finalizationStoppedDecision(d agentfinalizer.Decision, state *finalizationContinuationState) agentfinalizer.Decision {
	if d.Finalizable {
		return d
	}
	d.Finalized = false
	if d.Status == "" || d.Status == agentfinalizer.StatusCompleted || d.Status == agentfinalizer.StatusInProgress {
		d.Status = agentfinalizer.StatusBlocked
	}
	if state != nil {
		if state.StopStatus != "" && d.Status == agentfinalizer.StatusBlocked {
			d.Status = state.StopStatus
		}
		if state.StopReason != "" {
			d.MissingChecks = append(append([]string(nil), d.MissingChecks...), state.StopReason)
		}
	}
	return d
}

func applyFinalizationDecisionToResult(result *multiagent.RunResult, d agentfinalizer.Decision) {
	if result == nil {
		return
	}
	result.Status, result.CompletionReason = d.Status, d.CompletionReason
	result.Finalized, result.EvidenceVerified = d.Finalized, d.EvidenceVerified
	result.MissingChecks = append([]string(nil), d.MissingChecks...)
	result.EvidenceRefs = append([]string(nil), d.EvidenceRefs...)
	result.PendingExecutionIDs = append([]string(nil), d.PendingExecutionIDs...)
}

func (h *AgentHandler) hasPendingToolExecution(ids []string) bool {
	if h == nil || h.db == nil {
		return false
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		exec, err := h.db.GetToolExecution(id)
		if err != nil || exec == nil {
			continue
		}
		switch strings.TrimSpace(exec.Status) {
		case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning:
			return true
		}
	}
	return false
}

func (h *AgentHandler) waitFinalizationPendingExecutions(ctx context.Context, ids []string) bool {
	if !h.hasPendingToolExecution(ids) {
		return true
	}
	deadline := time.Now().Add(finalizationPendingWaitTimeout)
	for {
		if !h.hasPendingToolExecution(ids) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(finalizationPendingPollInterval):
		}
	}
}

func stopFinalizationForContext(ctx context.Context, state *finalizationContinuationState) bool {
	if ctx.Err() == nil {
		return false
	}
	state.StopReason = "运行上下文已结束，自动续跑已停止，进度与轨迹保留"
	if errors.Is(context.Cause(ctx), ErrTaskCancelled) {
		state.StopStatus = agentfinalizer.StatusCancelled
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		state.StopStatus = "timeout"
	}
	return true
}

func (h *AgentHandler) tryAutoContinueAfterFinalization(
	taskCtx context.Context,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	state *finalizationContinuationState,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if state == nil || decision.Finalizable || decision.Finalized {
		return false
	}
	if stopFinalizationForContext(taskCtx, state) || !observeFinalizationContinuation(decision, state) {
		return false
	}
	if result == nil || !multiagent.HasEinoResumeTrace(result) {
		state.StopReason = "缺少可恢复的代理轨迹，已阻断而非登记成功"
		return false
	}
	if decision.CompletionReason == agentfinalizer.ReasonPendingTools {
		if progressCallback != nil {
			progressCallback("finalization_waiting_tools", fmt.Sprintf("仍有 %d 个工具执行在运行，等待其结束后继续…", len(decision.PendingExecutionIDs)), map[string]interface{}{
				"conversationId": conversationID, "source": "finalizer", "status": decision.Status,
				"completionReason": decision.CompletionReason, "pendingExecutionIds": decision.PendingExecutionIDs,
				"waitTimeoutSeconds": int(finalizationPendingWaitTimeout / time.Second),
			})
		}
		if !h.waitFinalizationPendingExecutions(taskCtx, decision.PendingExecutionIDs) {
			state.StopReason = "等待后台工具结束已超时，已阻断并保留待完成执行 ID"
			stopFinalizationForContext(taskCtx, state)
			return false
		}
	}
	// Check the save result: otherwise a failed write can restore stale history
	// and falsely consume another repair attempt.
	if h == nil || h.db == nil {
		state.StopReason = "无法保存续跑轨迹，已阻断而非登记成功"
		return false
	}
	if err := h.db.SaveAgentTrace(conversationID, result.LastAgentTraceInput, result.LastAgentTraceOutput); err != nil {
		state.StopReason = "保存续跑轨迹失败，已阻断而非登记成功"
		if h.logger != nil {
			h.logger.Warn("finalization continuation trace save failed", zap.Error(err))
		}
		return false
	}
	hist, err := h.loadHistoryFromAgentTrace(conversationID)
	if err != nil || len(hist) == 0 {
		state.StopReason = "恢复续跑轨迹失败，已阻断并保留当前检查缺口"
		if h.logger != nil {
			h.logger.Warn("finalization auto-continue could not restore trace", zap.String("conversationId", conversationID), zap.Error(err))
		}
		return false
	}
	*curHistory = hist
	*curFinalMessage = ""
	var coverageChecksFile string
	if decision.CompletionReason == agentfinalizer.ReasonCoverageIncomplete {
		mcp.StartCoverageRepairBudget(taskCtx, finalizationCoverageRepairTimeout)
		root := ""
		if h.config != nil {
			root = h.config.MultiAgent.EinoMiddleware.ReductionRootDir
		}
		*curFinalMessage, coverageChecksFile = coverageContinuationMessage(decision.MissingChecks, tooloutput.SpillOpts{
			RootDir: root, ProjectID: h.conversationProjectID(conversationID), ConversationID: conversationID,
			ExecutionID: "coverage-checks-" + uuid.NewString() + ".json",
		})
	} else if decision.CompletionReason == agentfinalizer.ReasonIncompleteCandidate {
		if _, repairOnly := multiagent.FinalReportAfterCoverageRepair(result.Response, result.LastAgentTraceInput); repairOnly {
			*curFinalMessage = multiagent.FormatFinalReportContinueUserMessage()
		}
	}
	state.Attempts++
	if progressCallback != nil {
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId": conversationID, "source": "finalizer", "attempt": state.Attempts,
			"maxAttempts": finalizationContinuationLimit(decision), "status": decision.Status,
			"completionReason": decision.CompletionReason, "missingChecks": decision.MissingChecks,
			"coverageChecksFile": coverageChecksFile, "coverageValidFacts": decision.CoverageValidFacts,
			"coverageNoProgress": state.CoverageNoProgress, "coverageEvidenceExecutions": decision.CoverageEvidenceExecutions,
			"coverageUnresolvedGroups": decision.CoverageUnresolvedGroups, "repairTimeoutSeconds": int(finalizationCoverageRepairTimeout.Seconds()),
			"pendingExecutionIds": decision.PendingExecutionIDs,
			"contextInjection":    decision.CompletionReason == agentfinalizer.ReasonCoverageIncomplete,
		})
	}
	select {
	case <-taskCtx.Done():
		stopFinalizationForContext(taskCtx, state)
		return false
	case <-time.After(finalizationAutoContinueBackoff(state.Attempts)):
		return true
	}
}

const coverageContinuationHeader = multiagent.CoverageContinuationHeader

// With no artifact, preserve every check in full. Silent prefix-only feedback
// previously hid the exact malformed JS/source records the model had to repair.
func formatCoverageContinueMessage(checks []string) string {
	var b strings.Builder
	b.WriteString(coverageContinuationHeader)
	for _, check := range checks {
		b.WriteString("- " + strings.TrimSpace(check) + "\n")
	}
	return b.String()
}

func coverageContinuationMessage(checks []string, opts tooloutput.SpillOpts) (message, file string) {
	data, err := json.MarshalIndent(struct {
		MissingChecks []string `json:"missingChecks"`
	}{checks}, "", "  ")
	if err == nil {
		file, err = tooloutput.WriteTruncFile(opts, string(data))
	}
	if err != nil {
		return formatCoverageContinueMessage(checks), ""
	}
	var b strings.Builder
	b.WriteString(coverageContinuationHeader)
	fmt.Fprintf(&b, "完整 %d 条检查缺口（含具体字段/行号）已保存：%s\n必须使用 read_file 分段读取全部缺口；以下仅为前 20 条的短预览，不是完整清单。逐条核对事实，不得通过删除记录或降低库存计数绕过检查。\n", len(checks), file)
	for i, check := range checks {
		if i >= 20 {
			break
		}
		line := []rune(strings.TrimSpace(check))
		// Reserve room for the actionable repair instructions while keeping the
		// inline message bounded; the artifact above retains every check in full.
		const previewRunes = 180
		if len(line) > previewRunes {
			line = append(line[:previewRunes], []rune("…（完整诊断见文件）")...)
		}
		b.WriteString("- " + string(line) + "\n")
	}
	return b.String(), file
}

func finalizationAutoContinueBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 500 * time.Millisecond
	}
	return time.Duration(attempt) * time.Second
}
