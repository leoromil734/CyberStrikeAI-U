package agentfinalizer

import (
	"fmt"
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
)

const DeliveryKindPartialReport = "partial_report"

// PrepareStoppedDelivery is called ONLY after the execution/continuation loop
// has ended. blocked/failed/cancelled/timeout receive a partial report even when
// storage is unavailable or tools are still pending. RunTerminated describes the
// LOOP, not the tools or a completed assessment. Awaiting approval is not a stop.
//
// This is bounded, read-only assembly: no model/tool work, coverage repair, or
// persistence. FinalText, MissingChecks, pending snapshots, CompletionReason and
// the assessment progress are retained verbatim. A partial delivery never
// promotes a candidate, and cannot be used as evidence of successful completion.
func PrepareStoppedDelivery(db *database.DB, d Decision) Decision {
	d.DeliveryAvailable, d.RunTerminated = false, false
	d.DeliveryKind, d.DeliveryText = "", ""
	switch d.Status {
	case StatusBlocked, StatusFailed, StatusCancelled, "timeout":
		// A blocked human-approval handoff is not an ended execution loop.
		// An explicit cancellation/failure/timeout remains terminal even if its
		// earlier snapshot still mentions approval or pending tools.
		if d.Status == StatusBlocked && d.CompletionReason == ReasonAwaitingHITL {
			return d
		}
	default:
		if (d.Status == StatusCompleted || d.Status == StatusDeclined) && d.Finalizable && d.Finalized {
			d.RunTerminated = true
		}
		return d
	}

	snapshot := readStoppedDeliverySnapshot(db, strings.TrimSpace(d.ConversationID))
	var report, b strings.Builder
	b.WriteString("# 阶段报告（评估未完成）\n\n")
	b.WriteString("本次执行循环已停止。本报告汇总本会话可读取的保存记录和停止时决策快照，是不完整的阶段交付，不是完整评估通过证明。不能据此认定目标整体安全，未测试、未知、不可达或尚未完成的工具与候选项均不视为已验证安全。\n\n")

	b.WriteString("## 任务与停止原因\n\n")
	fmt.Fprintf(&b, "- 运行状态：%s\n- 停止说明：%s\n", stoppedStatusLabel(d.Status), stoppedReasonLabel(d.CompletionReason))
	if snapshot.ConversationKnown && strings.TrimSpace(snapshot.Title) != "" {
		fmt.Fprintf(&b, "- 任务标题（会话登记）：%s\n", reportInline(snapshot.Title))
	} else {
		b.WriteString("- 任务标题：无法读取或未登记，不能从模型候选正文推测任务范围。\n")
	}
	if snapshot.ProjectName != "" {
		fmt.Fprintf(&b, "- 绑定项目：%s\n", reportInline(snapshot.ProjectName))
	}
	fmt.Fprintf(&b, "- 会话：%s\n", reportInline(d.ConversationID))
	if d.CompletionReason != "" {
		fmt.Fprintf(&b, "- 原始停止代码（仅用于诊断）：%s\n", reportInline(d.CompletionReason))
	}
	writeStoppedScope(&b, snapshot.ScopeJSON)
	b.WriteString("\n")
	appendStoppedSection(&report, b.String(), 4000)
	b.Reset()

	b.WriteString("## 数据边界与可核实性\n\n")
	b.WriteString("只读取当前会话的执行元数据及与其当前项目绑定一致的漏洞登记，不借用其他会话的结果。各项为读取时快照，可能在运行停止后继续变化；报告中的登记标题、状态和数量均不等于重新核验结果。工具参数、原始凭据、大日志及模型候选全文不在本报告中展开。\n\n")
	if len(snapshot.Issues) > 0 {
		b.WriteString("**记录读取不完整／无法核实：**\n\n")
		for _, issue := range snapshot.Issues {
			fmt.Fprintf(&b, "- %s\n", issue) // Fixed messages, never raw database errors.
		}
		b.WriteString("\n")
	}
	if strings.TrimSpace(d.FinalText) != "" || strings.TrimSpace(d.CandidateReport) != "" {
		b.WriteString("已保留模型候选报告原文，供单独查看；其内容未核验，不并入本报告的成果，也不将候选中的通过比例或安全评价当作证据。\n\n")
	} else {
		b.WriteString("停止时没有可用的模型候选正文；本阶段报告仍保留已知进度与无法核实的限制。\n\n")
	}
	if len(d.EvidenceRefs) > 0 {
		fmt.Fprintf(&b, "决策快照保留 %d 条证据引用。本次不按这些引用跨会话检索，也不将引用数量当作已验证成果。\n\n", len(d.EvidenceRefs))
	}

	// Separate section budgets prevent hostile metadata from crowding out
	// findings, coverage limitations, data-read failures, or recovery advice.
	appendStoppedSection(&report, b.String(), 2000)
	b.Reset()
	writeStoppedTools(&b, d, snapshot)
	appendStoppedSection(&report, b.String(), 5000)
	b.Reset()
	writeStoppedFindings(&b, snapshot)
	appendStoppedSection(&report, b.String(), 4000)
	b.Reset()
	writeStoppedCoverage(&b, d)
	appendStoppedSection(&report, b.String(), 3000)

	// Reserve the ending for explicit recovery guidance even when metadata is
	// hostile or unusually long. No Decision field is truncated or rewritten.
	body, truncated := boundStoppedText(report.String(), stoppedReportMaxRunes-1200)
	if truncated {
		body += "\n\n（展示长度已达上限，其余记录未展开；不能把未展示项视为已完成。）\n"
	}
	b.Reset()
	b.WriteString(body)
	b.WriteString("\n## 恢复建议\n\n")
	b.WriteString("- 先恢复本会话记录的可读性，核对未完成执行 ID 的实际状态及已有漏洞证据；不要重复启动仍在运行的工具，也不要把运行停止等同于工具全部结束。\n")
	b.WriteString("- 根据具体缺口确认授权范围、排除项、身份条件和执行预算后，再单独恢复必要验证。完成态工具记录不等于漏洞已确认、目标安全或业务测试全部完成。\n")
	if d.CoverageRepairBlocked || mcp.IsAgentRunBudgetReason(d.CompletionReason) {
		b.WriteString("- 自动补写已受阻，应先按授权范围、候选当前性及业务功能分类核对；仅新增事实条目或统一标为 N/A 不能补足测试证据。\n")
	}
	b.WriteString("- 本次报告交付不会自动启动新的测试、调用模型、补写覆盖台账或改写资产。恢复后须重新核对证据及交付检查，方可判断是否满足完整报告要求。\n")

	d.DeliveryText = b.String()
	d.DeliveryKind = DeliveryKindPartialReport
	d.DeliveryAvailable, d.RunTerminated = true, true
	d.Finalizable, d.Finalized, d.EvidenceVerified = false, false, false
	return d
}

func writeStoppedTools(b *strings.Builder, d Decision, s stoppedDeliverySnapshot) {
	b.WriteString("## 已保存的工具执行\n\n")
	if s.ToolCountsKnown {
		other := s.ToolTotal - s.Completed - s.Failed - s.Queued - s.Running
		fmt.Fprintf(b, "本会话累计保存 %d 条工具执行：完成态 %d 条、失败 %d 条、排队 %d 条、运行中 %d 条、其他状态 %d 条。完成次数包含查询、文件操作或台账更新，不能当作漏洞验证次数。\n\n", s.ToolTotal, s.Completed, s.Failed, s.Queued, s.Running, other)
	} else {
		b.WriteString("本会话已保存工具执行总数及各状态数量无法核实，不将未知数量记为零。以下如有记录，仅表示本次成功读到的部分元数据。\n\n")
	}
	b.WriteString("执行循环停止不代表所有工具完成。")
	if len(d.PendingExecutionIDs) > 0 || len(d.PendingToolRuns) > 0 || d.CompletionReason == ReasonPendingTools {
		fmt.Fprintf(b, "停止时快照仍保留 %d 条待完成执行 ID、%d 条待完成工具运行记录；这些字段可能重叠，不相加作为工具总数。快照未再次核验，仍按未完成／待核对处理。", len(d.PendingExecutionIDs), len(d.PendingToolRuns))
	}
	if s.Queued+s.Running > 0 {
		fmt.Fprintf(b, "数据库仍登记 %d 条排队、%d 条运行中执行，均为未完成；本次报告不取消、不等待、不改写这些工具状态。", s.Queued, s.Running)
	} else {
		b.WriteString("数据库快照与运行快照均需结合核对，本次不会清除待完成记录或宣称所有工具已经结束。")
	}
	b.WriteString("\n\n")

	if len(s.ToolGroups) > 0 {
		var groups strings.Builder
		fmt.Fprintf(&groups, "按工具／原状态汇总（最多 %d 组）：\n\n", stoppedToolGroupLimit)
		for _, group := range s.ToolGroups {
			fmt.Fprintf(&groups, "- 工具：%s；状态：%s；记录数：%d。\n", reportInline(group.Name), reportInline(group.Status), group.Count)
		}
		if s.ToolGroupsCapped {
			groups.WriteString("- 其余工具／状态分组未展开，上述分组不是全部记录。\n")
		}
		groups.WriteString("\n")
		appendStoppedSection(b, groups.String(), 2000)
	}
	if len(s.Executions) > 0 {
		fmt.Fprintf(b, "可核对执行 ID（最多 %d 条，排队／运行中优先，其次按最近启动排序；只展示元数据）：\n\n", stoppedExecutionLimit)
		for _, execution := range s.Executions {
			fmt.Fprintf(b, "- 执行 ID：%s；工具：%s；原状态：%s。\n", reportInline(execution.ID), reportInline(execution.Name), reportInline(execution.Status))
		}
		if s.ExecutionsCapped {
			b.WriteString("- 其余执行 ID 未展开，请在本会话执行详情核对；抽样不改变总数或原状态。\n")
		}
		b.WriteString("\n")
	}
}

func writeStoppedFindings(b *strings.Builder, s stoppedDeliverySnapshot) {
	b.WriteString("## 已登记的发现\n\n")
	switch {
	case !s.FindingCountKnown:
		b.WriteString("本次未能完整读取该会话的漏洞登记数量，登记数量未知；请核对漏洞列表，不能按零漏洞理解。\n\n")
	case s.FindingCount == 0:
		b.WriteString("该会话在当前项目绑定下尚无已登记漏洞记录。这只说明登记情况，不等于已完成全部验证或目标不存在漏洞。HTTP 401、扫描候选和模型文字本身不作为漏洞确认依据。\n\n")
	default:
		fmt.Fprintf(b, "该会话在当前项目绑定下共登记 %d 条记录，以下最多展示 %d 条。\n\n", s.FindingCount, stoppedFindingLimit)
	}
	if len(s.Findings) > 0 {
		b.WriteString("保留原登记状态（包括待确认、误报等），不会升级为已确认漏洞；即使状态登记为 confirmed，也不代表本次重新验证。证据与复现步骤请查看漏洞详情。\n\n")
		for _, finding := range s.Findings {
			fmt.Fprintf(b, "- %s（级别：%s；登记状态：%s；记录：%s）\n", reportInline(finding.Title), reportInline(finding.Severity), reportInline(finding.Status), reportInline(finding.ID))
		}
		b.WriteString("\n")
	}
}

func writeStoppedCoverage(b *strings.Builder, d Decision) {
	b.WriteString("## 覆盖进度与具体缺口\n\n")
	// Report the caller's snapshot without recalculating coverage, inferring it
	// from model prose/fact counts, or changing its original diagnostic fields.
	if d.CoverageProgressKnown && d.CoverageInventoryGroups >= 0 && d.CoverageMappedGroups >= 0 && d.CoverageUnresolvedGroups >= 0 &&
		d.CoverageMappedGroups <= d.CoverageInventoryGroups && d.CoverageUnresolvedGroups == d.CoverageInventoryGroups-d.CoverageMappedGroups && d.CoverageEvidenceExecutions >= 0 {
		fmt.Fprintf(b, "停止时决策快照：独立候选库存共 **%d 组**；已有来源证据关联的处置记录 **%d 组**；仍未完成处置 **%d 组**；标记为已解析、完整且未过期的独立来源执行 %d 个。本次没有重新核验该快照；处置关联数量不是已验证安全数量，也不表示业务风险测试全部完成。\n\n", d.CoverageInventoryGroups, d.CoverageMappedGroups, d.CoverageUnresolvedGroups, d.CoverageEvidenceExecutions)
	} else {
		b.WriteString("当前独立候选库存与覆盖进度尚未完整核实，因此不提供推测的完成比例，也不将未知数量记为零。不会根据模型文字、事实条目数或工具完成次数推算覆盖率。\n\n")
		if !d.CoverageProgressKnown && d.CoverageInventoryGroups >= 0 && d.CoverageMappedGroups >= 0 && d.CoverageUnresolvedGroups >= 0 && d.CoverageEvidenceExecutions >= 0 &&
			(d.CoverageInventoryGroups > 0 || d.CoverageMappedGroups > 0 || d.CoverageUnresolvedGroups > 0 || d.CoverageEvidenceExecutions > 0) {
			fmt.Fprintf(b, "仅停止时观测值（总量及关联关系未核实）：库存 %d 组、处置关联 %d 组、未处置 %d 组、来源执行 %d 个。这些局部观测值不用于计算完成率，也不表示没有其他缺口。\n\n", d.CoverageInventoryGroups, d.CoverageMappedGroups, d.CoverageUnresolvedGroups, d.CoverageEvidenceExecutions)
		}
	}
	writeStoppedGaps(b, d.MissingChecks)
	if len(d.CoverageBlockers) > 0 {
		fmt.Fprintf(b, "另保留 %d 条原始覆盖阻碍记录，需在过程详情核对；不在此复制可能包含敏感信息的自由文本。\n\n", len(d.CoverageBlockers))
	}
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
		return "模型候选没有通过本次主代理的 exit 正式提交。"
	case ReasonMissingEvidence:
		return "缺少本次任务要求的完成态执行证据。"
	case ReasonEmptyResponse, ReasonIncompleteCandidate:
		return "模型没有提交可用于完整交付的报告正文。"
	case ReasonPendingTools:
		return "执行循环已停止，但仍有未完成或待核对的工具执行。"
	case ReasonAwaitingHITL:
		return "停止前记录仍涉及人工审批；本报告不授予审批、不自动恢复执行。"
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
