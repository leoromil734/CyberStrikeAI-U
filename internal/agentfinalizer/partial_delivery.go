package agentfinalizer

import (
	"fmt"
	"html"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
)

const DeliveryKindPartialReport = "partial_report"

// PrepareStoppedDelivery is called only after the execution/continuation loop
// has ended. It never promotes a candidate, changes the assessment outcome, or
// starts model/tool work. Pending tools and human approval remain fail-closed.
// The original FinalText and complete MissingChecks stay in the process record.
func PrepareStoppedDelivery(db *database.DB, d Decision) Decision {
	d.DeliveryAvailable, d.RunTerminated = false, false
	d.DeliveryKind, d.DeliveryText = "", ""
	if d.Finalizable && d.Finalized {
		d.RunTerminated = true
		return d
	}
	switch d.Status {
	case StatusBlocked, StatusFailed, StatusCancelled, "timeout":
	default:
		return d
	}
	if d.Finalizable || d.Finalized || db == nil || d.ConversationID == "" ||
		d.CompletionReason == ReasonAwaitingHITL || d.CompletionReason == ReasonPendingTools || len(d.PendingExecutionIDs) > 0 || len(d.PendingToolRuns) > 0 {
		return d
	}
	for _, check := range d.MissingChecks {
		lower := strings.ToLower(check)
		if strings.Contains(lower, "tool execution still queued or running") || strings.Contains(lower, "workflow is awaiting hitl approval") {
			return d
		}
	}
	if _, err := db.GetConversationLite(d.ConversationID); err != nil {
		return d
	}
	// Check the whole conversation, not just the last segment's IDs: detached
	// and prior-segment tools must not disappear when the root submits exit.
	rows, err := db.Query(`SELECT status, COUNT(*) FROM tool_executions WHERE conversation_id = ? GROUP BY status`, d.ConversationID)
	if err != nil {
		return d
	}
	counts := map[string]int{}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return d
		}
		counts[status] = count
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil || counts[mcp.ToolExecutionStatusQueued]+counts[mcp.ToolExecutionStatusRunning] > 0 {
		return d
	}

	projectID, err := db.GetConversationProjectID(d.ConversationID)
	if err != nil {
		return d
	}
	projectName := ""
	if projectID != "" {
		projectName, _ = db.GetProjectName(projectID)
	}
	// Early failure/cancellation decisions can precede coverage inspection.
	// Read the existing persisted policy rather than inferring it from prose.
	if !d.CoverageProgressKnown {
		if run, err := db.LatestAssessmentRun(d.ConversationID); err == nil && run != nil && run.Mode == database.AssessmentModeComprehensive {
			coverage := coverageForDelivery(db, Input{ConversationID: d.ConversationID, AssistantMessageID: d.AssistantMessageID, RequireCoverageEvidence: true})
			d.setCoverageProgress(coverage.Progress)
		}
	}

	var b strings.Builder
	b.WriteString("# 阶段报告（评估未完成）\n\n")
	b.WriteString("## 本次运行结论\n\n本次运行已停止，以下是依据已保存记录生成的阶段交付，不是完整评估通过证明。覆盖与证据检查尚未全部通过，不能据此认定目标整体安全，也不能将未测试、未知或不可达的候选项视为已验证安全。\n\n")
	if projectName != "" {
		fmt.Fprintf(&b, "- 项目：%s\n", reportInline(projectName))
	}
	fmt.Fprintf(&b, "- 会话：%s\n- 运行状态：%s\n- 停止说明：%s\n\n", reportInline(d.ConversationID), stoppedStatusLabel(d.Status), stoppedReasonLabel(d.CompletionReason))

	b.WriteString("## 已保存的执行与证据\n\n")
	fmt.Fprintf(&b, "本会话累计保存 %d 条完成态工具执行记录，%d 条失败记录。工具完成次数包含查询、文件操作或台账更新，不能当作漏洞验证次数。原始输出、执行轨迹和候选报告保留在过程详情中。\n\n", counts[mcp.ToolExecutionStatusCompleted], counts[mcp.ToolExecutionStatusFailed])
	if d.CoverageProgressKnown {
		fmt.Fprintf(&b, "当前评估的独立候选库存共 **%d 组**；已有来源证据关联的处置记录 **%d 组**；仍未完成处置 **%d 组**。已解析、完整且未过期的独立来源执行为 %d 个。处置关联数量不是已验证安全数量，也不表示业务风险测试全部完成。\n\n", d.CoverageInventoryGroups, d.CoverageMappedGroups, d.CoverageUnresolvedGroups, d.CoverageEvidenceExecutions)
	} else {
		b.WriteString("当前独立候选库存与覆盖进度尚未完整核实，因此不提供推测的完成比例，也不将未知数量记为零。\n\n")
	}

	b.WriteString("## 已登记的发现\n\n")
	filter := database.VulnerabilityListFilter{ConversationID: d.ConversationID, ProjectID: projectID}
	count, countErr := db.CountVulnerabilities(filter)
	findings, findingsErr := db.ListVulnerabilitySummariesForAccess(20, 0, filter, database.RBACListAccess{})
	switch {
	case countErr != nil || findingsErr != nil:
		b.WriteString("本次未能完整读取该会话的漏洞登记记录，登记数量未知；请在漏洞列表核对，不能按零漏洞理解。\n\n")
	case count == 0:
		b.WriteString("该会话尚无已登记漏洞记录。这只说明当前登记情况，不等于已完成全部验证或目标不存在漏洞。HTTP 401、扫描候选和模型文字本身不作为漏洞确认依据。\n\n")
	default:
		fmt.Fprintf(&b, "该会话共登记 %d 条记录，以下最多展示 20 条。这里保留原登记状态，不把待确认或误报记录升级为已确认漏洞；证据与复现步骤请查看漏洞详情。\n\n", count)
		for _, finding := range findings {
			fmt.Fprintf(&b, "- %s（级别：%s；登记状态：%s；记录：%s）\n", reportInline(finding.Title), reportInline(finding.Severity), reportInline(finding.Status), reportInline(finding.ID))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 未完成范围与后续建议\n\n")
	b.WriteString("- 覆盖台账、候选库存或执行证据仍有未通过的检查项，当前不能形成全面评估成功结论。\n")
	if len(d.MissingChecks) > 0 {
		fmt.Fprintf(&b, "- 本次保留 %d 条完整检查诊断，详见过程详情中的最终回复检查记录；此处不重复内部字段清单。\n", len(d.MissingChecks))
	}
	if d.CoverageRepairBlocked || mcp.IsAgentRunBudgetReason(d.CompletionReason) {
		b.WriteString("- 已停止自动逐条补写；应先核实授权范围、候选当前性和业务功能分类。仅新增 fact 或统一标为 N/A 不能补足测试证据。\n")
	}
	b.WriteString("- 后续应从明确的缺口和可复核证据开始，在确认范围、凭据及执行预算后再单独恢复任务。本次报告交付不会自动启动新的测试。\n")
	b.WriteString("- 普通助手输出及未通过检查的候选报告仍可在过程详情查看，但其中的整体安全评价不属于本次已交付结论。\n")

	d.DeliveryText = b.String()
	d.DeliveryKind = DeliveryKindPartialReport
	d.DeliveryAvailable, d.RunTerminated = true, true
	// A partial report never upgrades either the run status or its evidence.
	d.Finalizable, d.Finalized, d.EvidenceVerified = false, false, false
	return d
}

func reportInline(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) > 240 {
		s = string(runes[:240]) + "…"
	}
	s = html.EscapeString(s)
	return strings.NewReplacer("\\", "\\\\", "*", "\\*", "_", "\\_", "`", "\\`", "[", "\\[", "]", "\\]", "#", "\\#", "!", "\\!").Replace(s)
}

func stoppedStatusLabel(status string) string {
	switch status {
	case StatusCancelled:
		return "已取消，评估未完成"
	case StatusFailed:
		return "执行失败，评估未完成"
	case "timeout":
		return "已超时，评估未完成"
	default:
		return "已停止，完整交付检查未通过"
	}
}

func stoppedReasonLabel(reason string) string {
	switch reason {
	case ReasonCoverageIncomplete:
		return "覆盖记录与独立候选库存等检查尚未满足完整评估要求。"
	case ReasonReportNotSubmitted:
		return "模型产生了报告候选，但没有通过本次主代理的 exit 正式提交。"
	case ReasonMissingEvidence:
		return "缺少本次任务要求的完成态执行证据。"
	case ReasonEmptyResponse, ReasonIncompleteCandidate:
		return "模型没有提交可用于完整交付的报告正文。"
	case ReasonCancelled:
		return "运行已取消，已保存的进度予以保留。"
	case "timeout":
		return "运行达到时限，已保存的进度予以保留。"
	case ReasonUpstreamErrorText, ReasonFailed:
		return "模型或执行链发生错误，本次未完成。"
	default:
		if mcp.IsAgentRunBudgetReason(reason) {
			return "运行达到本次事实写入或覆盖补写预算，自动补写已停止。"
		}
		return "运行已经停止，但完整评估尚未通过交付检查；具体停止记录保留在过程详情。"
	}
}
