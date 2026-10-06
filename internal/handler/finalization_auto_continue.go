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
	finalizationAutoContinueMaxAttempts = 4
	finalizationCoverageMaxAttempts     = 64
	finalizationCoverageNoProgressLimit = 2
	// The first observation only records the evidence high water. Each later
	// segment without a new real execution counts. Three such segments stop
	// the loop and deliver a phase report; ledger rows never renew this.
	finalizationCoverageStagnationLimit = 3
	finalizationPendingWaitTimeout      = 20 * time.Minute
	finalizationPendingPollInterval     = 5 * time.Second
)

// A bounded continuation budget belongs to this request, not to a model response.
// Work and report delivery have separate allowances. New fact rows or a shorter
// error list are not progress; only a new real execution can renew the
// consecutive-stagnation allowance. Ledger mappings cannot.
type finalizationContinuationState struct {
	Attempts                    int // Total restored segments; diagnostic only.
	WorkAttempts                int
	DeliveryAttempts            int
	CoverageObserved            bool
	CoverageValidFactsHighWater int
	CoverageEvidenceHighWater   int
	CoverageMappedHighWater     int
	CoverageNoProgress          int
	// WorkMode changes the next action, never the coverage proof or task scope.
	WorkMode            string
	LastReportCandidate string
	StopReason          string
	StopStatus          string
}

func finalizationNeedsCoverageWork(d agentfinalizer.Decision) bool {
	switch d.CompletionReason {
	case agentfinalizer.ReasonCoverageIncomplete, agentfinalizer.ReasonMissingEvidence, agentfinalizer.ReasonPendingTools:
		return true
	}
	// An empty/short candidate must not hide still executable inventory work.
	return d.CoverageRepairBlocked || d.CoverageUnresolvedGroups > 0
}

func finalizationContinuationLimit(d agentfinalizer.Decision) int {
	if finalizationNeedsCoverageWork(d) {
		return finalizationCoverageMaxAttempts
	}
	return finalizationAutoContinueMaxAttempts
}

func (s *finalizationContinuationState) usedAttempts(d agentfinalizer.Decision) int {
	if finalizationNeedsCoverageWork(d) {
		return s.WorkAttempts
	}
	return s.DeliveryAttempts
}

// Call only after the exact current trace was saved and restored successfully.
func (s *finalizationContinuationState) recordContinuation(d agentfinalizer.Decision) {
	s.Attempts++
	if finalizationNeedsCoverageWork(d) {
		s.WorkAttempts++
	} else {
		s.DeliveryAttempts++
	}
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
		agentfinalizer.ReasonPendingTools, agentfinalizer.ReasonIncompleteCandidate,
		agentfinalizer.ReasonReportNotSubmitted, agentfinalizer.ReasonEmptyResponse:
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
	used := state.usedAttempts(d)
	if !shouldAutoContinueAfterFinalization(d, used) {
		if used >= finalizationContinuationLimit(d) {
			phase := "报告收尾"
			if finalizationNeedsCoverageWork(d) {
				phase = "实际工作"
			}
			state.StopReason = fmt.Sprintf("%s自动续跑已达到本次运行的 %d 段硬上限，检查仍未通过；保留轨迹供人工修复后恢复", phase, finalizationContinuationLimit(d))
		}
		return false
	}
	if finalizationNeedsCoverageWork(d) {
		state.WorkMode = "coverage_work"
		if d.CoverageRepairBlocked {
			// Large/unknown raw inventory forbids mechanical fact inflation,
			// not investigation. Reclassify within scope and verify real work.
			state.WorkMode = "classify_and_verify"
		}
		// Ledger rows do not renew the run. Only a new real execution does.
		progress := d.CoverageProgressKnown && d.CoverageEvidenceExecutions > state.CoverageEvidenceHighWater
		if state.CoverageObserved {
			if progress {
				state.CoverageNoProgress = 0
			} else {
				state.CoverageNoProgress++
			}
		}
		state.CoverageObserved = true
		if d.CoverageProgressKnown && d.CoverageEvidenceExecutions > state.CoverageEvidenceHighWater {
			state.CoverageEvidenceHighWater = d.CoverageEvidenceExecutions
		}
		if d.CoverageProgressKnown && d.CoverageMappedGroups > state.CoverageMappedHighWater {
			state.CoverageMappedHighWater = d.CoverageMappedGroups
		}
		if d.CoverageValidFacts > state.CoverageValidFactsHighWater {
			state.CoverageValidFactsHighWater = d.CoverageValidFacts
		}
		if state.CoverageNoProgress >= finalizationCoverageNoProgressLimit {
			state.WorkMode = "classify_and_verify"
		}
		if state.CoverageNoProgress >= finalizationCoverageStagnationLimit {
			state.StopReason = fmt.Sprintf("已连续 %d 段未新增可核查执行证据；台账和事实补写不算进展。停止续跑并按现有证据交付阶段报告，未处置组保留为未覆盖，不视为已验证安全", state.CoverageNoProgress)
			return false
		}
	} else {
		state.WorkMode = "deliver_report"
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
		if state.LastReportCandidate != "" {
			d.CandidateReport = state.LastReportCandidate
		}
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

func (h *AgentHandler) pendingFinalizationTools(ctx context.Context, conversationID string, ids []string) ([]string, error) {
	if h == nil || h.db == nil {
		return nil, errors.New("无法核实后台工具状态：数据库不可用")
	}
	if conversationID != "" {
		rows, err := h.db.QueryContext(ctx, `SELECT id FROM tool_executions WHERE conversation_id = ? AND status IN ('queued', 'running') ORDER BY id`, conversationID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var pending []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			pending = append(pending, id)
		}
		return pending, rows.Err()
	}
	var pending []string
	for _, id := range ids {
		execution, err := h.db.GetToolExecution(id)
		if err != nil || execution == nil {
			return nil, fmt.Errorf("无法核实后台工具 %s 的状态", id)
		}
		if execution.Status == mcp.ToolExecutionStatusQueued || execution.Status == mcp.ToolExecutionStatusRunning {
			pending = append(pending, id)
		}
	}
	return pending, nil
}

func finalizationToolWaitDeadline(ctx context.Context) time.Time {
	// Real requests already have an absolute deadline and each tool its own
	// timeout. Do not terminate a legitimate long tool after an arbitrary 20m.
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(finalizationPendingWaitTimeout)
}

func (h *AgentHandler) waitFinalizationPendingExecutions(ctx context.Context, conversationID string, ids []string) error {
	deadline := finalizationToolWaitDeadline(ctx)
	for {
		if err := agentRunContextError(ctx); err != nil {
			return err
		}
		pending, err := h.pendingFinalizationTools(ctx, conversationID, ids)
		if err != nil {
			return err // an unreadable state never means completed
		}
		if len(pending) == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
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
	if result != nil && (result.ReportSubmitted || multiagent.IsAssessmentReportCandidate(decision.FinalText)) && strings.TrimSpace(decision.FinalText) != "" {
		state.LastReportCandidate = decision.FinalText
	}
	if stopFinalizationForContext(taskCtx, state) {
		return false
	}
	// exit submits a candidate, never permission to discard running tools or
	// executable gaps. Wait first, even when the continuation count is spent.
	if decision.Status == agentfinalizer.StatusAwaitingHITL || decision.Status == agentfinalizer.StatusCancelled || decision.Status == agentfinalizer.StatusFailed {
		return false
	}
	if decision.CompletionReason == agentfinalizer.ReasonPendingTools || len(decision.PendingExecutionIDs) > 0 {
		if progressCallback != nil {
			progressCallback("finalization_waiting_tools", fmt.Sprintf("仍有 %d 个工具执行在运行，等待其结束后核对证据与报告…", len(decision.PendingExecutionIDs)), map[string]interface{}{
				"conversationId": conversationID, "source": "finalizer", "status": decision.Status,
				"completionReason": decision.CompletionReason, "pendingExecutionIds": decision.PendingExecutionIDs,
				"waitTimeoutSeconds": int(time.Until(finalizationToolWaitDeadline(taskCtx)).Seconds()),
			})
		}
		if err := h.waitFinalizationPendingExecutions(taskCtx, conversationID, decision.PendingExecutionIDs); err != nil {
			state.StopReason = "无法等到后台工具完成：" + err.Error() + "；保留未完成执行记录并交付阶段报告"
			stopFinalizationForContext(taskCtx, state)
			return false
		}
	}
	if err := h.waitFinalizationIngestion(taskCtx, conversationID, progressCallback); err != nil {
		state.StopReason = "原件入库未能完成：" + err.Error() + "；保留真实缺口并交付阶段报告"
		stopFinalizationForContext(taskCtx, state)
		return false
	}
	if !observeFinalizationContinuation(decision, state) {
		return false
	}
	if result == nil || !multiagent.HasEinoResumeTrace(result) {
		state.StopReason = "缺少可恢复的代理轨迹，已阻断而非登记成功"
		return false
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
	if finalizationNeedsCoverageWork(decision) {
		// This segment performs real classification/verification, not a timed
		// bookkeeping loop. The request deadline and tool budgets still apply.
		root := ""
		if h.config != nil {
			root = h.config.MultiAgent.EinoMiddleware.ReductionRootDir
		}
		if state.WorkMode == "classify_and_verify" {
			// The disposition checklist is what pulled the model back into
			// ledger repair. Keep it out of this prompt, including the file path.
			*curFinalMessage = classifyAndVerifyContinuationMessage(decision)
		} else {
			*curFinalMessage, coverageChecksFile = coverageContinuationMessage(decision.MissingChecks, tooloutput.SpillOpts{
				RootDir: root, ProjectID: h.conversationProjectID(conversationID), ConversationID: conversationID,
				ExecutionID: "coverage-checks-" + uuid.NewString() + ".json",
			})
		}
	} else {
		*curFinalMessage = finalizationResumeInstruction(decision)
		if decision.CompletionReason == agentfinalizer.ReasonIncompleteCandidate {
			if _, repairOnly := multiagent.FinalReportAfterCoverageRepair(result.Response, result.LastAgentTraceInput); repairOnly {
				*curFinalMessage = multiagent.FormatFinalReportContinueUserMessage()
			}
		}
	}
	state.recordContinuation(decision)
	if progressCallback != nil {
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId": conversationID, "source": "finalizer", "attempt": state.Attempts,
			"maxAttempts": finalizationContinuationLimit(decision), "phaseAttempt": state.usedAttempts(decision),
			"workAttempts": state.WorkAttempts, "deliveryAttempts": state.DeliveryAttempts, "status": decision.Status,
			"completionReason": decision.CompletionReason, "missingChecks": decision.MissingChecks,
			"coverageChecksFile": coverageChecksFile, "coverageValidFacts": decision.CoverageValidFacts,
			"coverageNoProgress": state.CoverageNoProgress, "coverageEvidenceExecutions": decision.CoverageEvidenceExecutions,
			"coverageUnresolvedGroups": decision.CoverageUnresolvedGroups, "coverageMappedGroups": decision.CoverageMappedGroups, "workMode": state.WorkMode,
			"bookkeepingRepairStopped": state.WorkMode == "classify_and_verify",
			"pendingExecutionIds":      decision.PendingExecutionIDs,
			"contextInjection":         finalizationNeedsCoverageWork(decision),
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

func finalizationResumeInstruction(d agentfinalizer.Decision) string {
	prefix := "【系统交付修复 / Final report required】\nexit 仅表示请求收尾，当前检查尚未通过；继续基于已有轨迹完成实际工作，禁止只说接下来做什么就结束。"
	if d.CompletionReason == agentfinalizer.ReasonPendingTools {
		return prefix + "后台工具已结束，请先实际读取执行结果、保留失败/超时范围，重新核对覆盖与证据，然后提交包含成果、证据、未完成范围的完整报告。不要仅复述旧报告。"
	}
	return prefix + "已有草稿/exit 内容不代表任务完成。先处理仍可执行的缺口；报告须包含实际成果与证据、负结果及限制。Deep/Supervisor 根角色用 exit.final_result 提交完整正文，其他模式正常返回报告。\n当前检查原因：" + d.CompletionReason
}

const coverageContinuationHeader = multiagent.CoverageWorkContinuationHeader

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

func isLedgerDispositionCheck(check string) bool {
	check = strings.ToLower(check)
	return strings.Contains(check, "has no matching ledger disposition") ||
		strings.Contains(check, "independent discovery inventory:") ||
		strings.Contains(check, "additional independent discovery groups lack") ||
		strings.Contains(check, "inventory_group_key")
}

func classifyAndVerifyContinuationMessage(d agentfinalizer.Decision) string {
	var actionable []string
	for _, check := range d.MissingChecks {
		if isLedgerDispositionCheck(check) {
			continue
		}
		line := []rune(strings.TrimSpace(check))
		if len(line) > 180 {
			line = append(line[:180], []rune("…")...)
		}
		actionable = append(actionable, string(line))
		if len(actionable) == 5 {
			break
		}
	}
	var b strings.Builder
	b.WriteString("【系统自动续跑 / Auto resume】\n结构化覆盖检查尚未通过。本段是分类与验证，不是账本补写。\n")
	fmt.Fprintf(&b, "【分类与验证续跑】独立候选 %d 组，已关联处置 %d 组，未处置 %d 组，可核验执行 %d 个，计数是否完整核实=%t。第三方主机、平台 JS 和纯静态资源保留为未覆盖限制，不要逐条写端点事实，不要查询或补写发现组绑定，不要打开覆盖检查文件，不要把未测地址写成 N/A、negated 或已安全。\n", d.CoverageInventoryGroups, d.CoverageMappedGroups, d.CoverageUnresolvedGroups, d.CoverageEvidenceExecutions, d.CoverageProgressKnown)
	b.WriteString("先测用户所给域名下还没测过的关联资产：子域、同注册域、证书或同一运营主体指向的域名，以及这些域名解析到的非 CDN 源站 IP。支付、验证码、社交、统计挂件和纯静态资源不是关联资产，不要为它们扩测。关联域名或源站 IP 尚未测试、也没有证据 blocked 时，不要交卷。\n")
	b.WriteString("然后再验证仍可能造成实际危害的认证、越权、注入、敏感数据或后台入口，确认危害后立即记录漏洞。关联资产已测完或已 blocked，且没有新的可验证危害，再交付完整报告，并写明未处置组仍未覆盖。\n")
	if len(actionable) > 0 {
		b.WriteString("与账本抄写无关、仍可执行的检查（最多 5 条）：\n")
		for _, check := range actionable {
			b.WriteString("- " + check + "\n")
		}
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
	fmt.Fprintf(&b, "检查缺口共 %d 条，文件只供抽看：%s\n不要通读，不要逐条补事实或把未测地址写成不适用。下面最多 5 条用来挑选可能造成实际危害的验证；其余保持未测缺口。\n", len(checks), file)
	for i, check := range checks {
		if i >= 5 {
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
	if attempt > 5 {
		attempt = 5
	}
	return time.Duration(attempt) * time.Second
}
