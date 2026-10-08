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
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/tooloutput"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	finalizationAutoContinueMaxAttempts = 4
	// finalizationCoverageMaxAttempts 是覆盖续跑的段数安全上限默认值。
	// 正常停止由停滞时间窗（默认 90 分钟无新增可核查进展）决定，而不是段数；
	// 该上限只用于兜底病态快段空转，达到时保留轨迹供人工恢复。
	finalizationCoverageMaxAttempts     = config.DefaultCoverageContinuationMaxSegments
	finalizationCoverageNoProgressLimit = 2
	finalizationPendingWaitTimeout      = 20 * time.Minute
	finalizationPendingPollInterval     = 5 * time.Second
)

// A bounded continuation budget belongs to this request, not to a model response.
// Work and report delivery have separate allowances. New fact rows or a shorter
// error list are not progress; only a new real execution can renew the
// stagnation clock. Ledger mappings cannot.
//
// Loop Engineering（时间窗停滞治理）：覆盖续跑的停止条件 = 距上次可核查进展
// （新漏洞验证执行 / 新侦察来源执行 / 新测试面发现，任一）达到 StagnationWindow
// （默认 90 分钟，可配置）。CoverageNoProgress 只用于切换工作策略，不再直接停止；
// CoverageMaxSegments 只是防病态快段的安全上限。
type finalizationContinuationState struct {
	Attempts                    int // Total restored segments; diagnostic only.
	WorkAttempts                int
	DeliveryAttempts            int
	CoverageObserved            bool
	CoverageValidFactsHighWater int
	CoverageEvidenceHighWater   int
	CoverageMappedHighWater     int
	VerificationHighWater       int
	CoverageInventoryHighWater  int
	CoverageNoProgress          int
	// 时间窗停滞治理字段：StartedAt/LastProgressAt 记录停滞时钟；窗口与段数上限由配置注入。
	StartedAt           time.Time
	LastProgressAt      time.Time
	StagnationWindow    time.Duration
	CoverageMaxSegments int
	// WorkMode changes the next action, never the coverage proof or task scope.
	WorkMode            string
	LastReportCandidate string
	StopReason          string
	StopStatus          string
}

// applyContinuationPolicy 注入停滞窗口与段数上限；未配置时保持默认值（90 分钟 / 512 段）。
func (s *finalizationContinuationState) applyContinuationPolicy(cfg *config.Config) {
	if s.StagnationWindow <= 0 {
		s.StagnationWindow = config.DefaultCoverageContinuationStagnationWindow
		if cfg != nil {
			s.StagnationWindow = cfg.MultiAgent.EinoMiddleware.CoverageContinuationStagnationEffective()
		}
	}
	if s.CoverageMaxSegments <= 0 {
		s.CoverageMaxSegments = config.DefaultCoverageContinuationMaxSegments
		if cfg != nil {
			s.CoverageMaxSegments = cfg.MultiAgent.EinoMiddleware.CoverageContinuationMaxSegmentsEffective()
		}
	}
}

func (s *finalizationContinuationState) stagnationWindow() time.Duration {
	if s.StagnationWindow > 0 {
		return s.StagnationWindow
	}
	return config.DefaultCoverageContinuationStagnationWindow
}

func (s *finalizationContinuationState) coverageMaxSegments() int {
	if s.CoverageMaxSegments > 0 {
		return s.CoverageMaxSegments
	}
	return finalizationCoverageMaxAttempts
}

func (s *finalizationContinuationState) continuationLimit(d agentfinalizer.Decision) int {
	if finalizationNeedsCoverageWork(d) {
		return s.coverageMaxSegments()
	}
	return finalizationAutoContinueMaxAttempts
}

func (s *finalizationContinuationState) shouldAutoContinue(d agentfinalizer.Decision, attempt int) bool {
	return shouldAutoContinueWithinLimit(d, attempt, s.continuationLimit(d))
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
	return shouldAutoContinueWithinLimit(d, attempt, finalizationContinuationLimit(d))
}

// shouldAutoContinueWithinLimit 判定当前段是否允许进入下一段续跑（含原因白名单与上限检查）。
func shouldAutoContinueWithinLimit(d agentfinalizer.Decision, attempt, limit int) bool {
	if d.Finalizable || d.Finalized || attempt >= limit {
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
	return observeFinalizationContinuationAt(d, state, time.Now())
}

// observeFinalizationContinuationAt 是 Loop Engineering 的核心判定（时间窗停滞治理）：
//   - 停止条件 = 距上次可核查进展达到停滞窗口（默认 90 分钟），而不是连续固定段数；
//   - 可核查进展（任一信号即重置停滞时钟）：
//     1）新的漏洞验证执行（VerificationExecutions：record_vulnerability 及各验证器）；
//     2）新的侦察来源执行（CoverageEvidenceExecutions：新测试面被核实）；
//     3）新的测试脆弱面（CoverageInventoryGroups：独立候选库存增长）；
//   - 台账映射、事实补写、文件读写与普通 shell 探测不算进展；
//   - 连续无进展段数（CoverageNoProgress）只用于切换工作策略，不再直接停止；
//   - 段数安全上限（CoverageMaxSegments）只兜底病态快段空转。
func observeFinalizationContinuationAt(d agentfinalizer.Decision, state *finalizationContinuationState, now time.Time) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	used := state.usedAttempts(d)
	if !state.shouldAutoContinue(d, used) {
		if used >= state.continuationLimit(d) {
			phase := "报告收尾"
			if finalizationNeedsCoverageWork(d) {
				phase = "实际工作"
			}
			state.StopReason = fmt.Sprintf("%s自动续跑已达到本次运行的 %d 段安全上限，检查仍未通过；保留轨迹供人工修复后恢复", phase, state.continuationLimit(d))
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
		// 停滞时钟起点：首次观察时初始化，保证窗口从任务进入覆盖工作阶段就开始计时。
		if state.LastProgressAt.IsZero() {
			state.StartedAt, state.LastProgressAt = now, now
		}
		// Ledger rows do not renew the clock. A new recon source, a new completed
		// vulnerability-verification tool, or newly discovered test surface does.
		// Fact writes and file reads do not.
		progress := (d.CoverageProgressKnown && d.CoverageEvidenceExecutions > state.CoverageEvidenceHighWater) ||
			d.VerificationExecutions > state.VerificationHighWater ||
			(d.CoverageProgressKnown && d.CoverageInventoryGroups > state.CoverageInventoryHighWater)
		if state.CoverageObserved {
			if progress {
				state.CoverageNoProgress = 0
			} else {
				state.CoverageNoProgress++
			}
		}
		state.CoverageObserved = true
		if progress {
			state.LastProgressAt = now
		}
		if d.CoverageProgressKnown && d.CoverageEvidenceExecutions > state.CoverageEvidenceHighWater {
			state.CoverageEvidenceHighWater = d.CoverageEvidenceExecutions
		}
		if d.CoverageProgressKnown && d.CoverageMappedGroups > state.CoverageMappedHighWater {
			state.CoverageMappedHighWater = d.CoverageMappedGroups
		}
		if d.CoverageValidFacts > state.CoverageValidFactsHighWater {
			state.CoverageValidFactsHighWater = d.CoverageValidFacts
		}
		if d.VerificationExecutions > state.VerificationHighWater {
			state.VerificationHighWater = d.VerificationExecutions
		}
		if d.CoverageProgressKnown && d.CoverageInventoryGroups > state.CoverageInventoryHighWater {
			state.CoverageInventoryHighWater = d.CoverageInventoryGroups
		}
		if state.CoverageNoProgress >= finalizationCoverageNoProgressLimit {
			state.WorkMode = "classify_and_verify"
		}
		window := state.stagnationWindow()
		if stagnant := now.Sub(state.LastProgressAt); stagnant >= window {
			state.StopReason = fmt.Sprintf("已连续 %s 未新增可核查进展（停滞窗口 %s）：新漏洞验证、新的侦察来源执行或新的测试面发现都会重新起算；台账与事实补写不算进展。停止续跑并按现有证据交付阶段报告，未处置组保留为未覆盖，不视为已验证安全",
				formatStagnationDuration(stagnant), formatStagnationDuration(window))
			return false
		}
	} else {
		state.WorkMode = "deliver_report"
	}
	return true
}

// formatStagnationDuration 把停滞时长格式化为人类可读的中文文本。
func formatStagnationDuration(d time.Duration) string {
	if d <= 0 {
		return "0 分钟"
	}
	hours := int(d / time.Hour)
	minutes := int((d % time.Hour) / time.Minute)
	switch {
	case hours > 0 && minutes > 0:
		return fmt.Sprintf("%d 小时 %d 分钟", hours, minutes)
	case hours > 0:
		return fmt.Sprintf("%d 小时", hours)
	default:
		return fmt.Sprintf("%d 分钟", minutes)
	}
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
	// 时间窗停滞治理：先注入配置的停滞窗口/段数上限，默认 90 分钟 / 512 段。
	var continuationCfg *config.Config
	if h != nil {
		continuationCfg = h.config
	}
	state.applyContinuationPolicy(continuationCfg)
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
		stagnantSeconds, nextStopAt := 0, state.LastProgressAt.Add(state.stagnationWindow())
		if !state.LastProgressAt.IsZero() {
			stagnantSeconds = int(time.Since(state.LastProgressAt).Seconds())
		}
		progressCallback("finalization_auto_continue", "最终回复检查尚未收敛，正在基于已有轨迹继续执行…", map[string]interface{}{
			"conversationId": conversationID, "source": "finalizer", "attempt": state.Attempts,
			"maxAttempts": state.continuationLimit(decision), "phaseAttempt": state.usedAttempts(decision),
			"workAttempts": state.WorkAttempts, "deliveryAttempts": state.DeliveryAttempts, "status": decision.Status,
			"completionReason": decision.CompletionReason, "missingChecks": decision.MissingChecks,
			"coverageChecksFile": coverageChecksFile, "coverageValidFacts": decision.CoverageValidFacts,
			"coverageNoProgress": state.CoverageNoProgress, "coverageEvidenceExecutions": decision.CoverageEvidenceExecutions,
			"coverageUnresolvedGroups": decision.CoverageUnresolvedGroups, "coverageMappedGroups": decision.CoverageMappedGroups, "workMode": state.WorkMode,
			"bookkeepingRepairStopped": state.WorkMode == "classify_and_verify",
			"pendingExecutionIds":      decision.PendingExecutionIDs,
			"contextInjection":         finalizationNeedsCoverageWork(decision),
			// 时间窗停滞治理诊断：距上次可核查进展的时长、窗口、下次可停止时间与库存信号。
			"stagnationWindowSeconds": int(state.stagnationWindow().Seconds()),
			"stagnantSeconds":         stagnantSeconds,
			"stagnantWindow":          formatStagnationDuration(state.stagnationWindow()),
			"lastProgressAt":          state.LastProgressAt,
			"nextStopEligibleAt":      nextStopAt,
			"coverageInventoryGroups": decision.CoverageInventoryGroups,
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
	b.WriteString(coverageContinuationHeader)
	fmt.Fprintf(&b, "独立候选 %d 组，未处置 %d 组。不要写端点事实，不要打开覆盖检查文件；按已有证据选择高价值线索，原始库存数量不等于需逐一测试的业务单元。\n", d.CoverageInventoryGroups, d.CoverageUnresolvedGroups)
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
	fmt.Fprintf(&b, "检查缺口共 %d 条，全部缺口保留在原件：%s\n仅对所选高价值候选用 read_file 按需抽看，不要通读，不要逐条补事实或把未测地址写成不适用。下面最多 5 条用来挑选可能造成实际危害的验证；其余保持未测缺口。\n", len(checks), file)
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
