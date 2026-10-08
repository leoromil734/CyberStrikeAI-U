package agentfinalizer

import (
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
)

const independentInventorySampleLimit = 30

func checkIndependentInventory(db *database.DB, projectID, conversationID, assessmentID string, facts []coverage.Fact, report *coverage.Report) CoverageProgress {
	progress := CoverageProgress{}
	if db == nil || projectID == "" || conversationID == "" || assessmentID == "" {
		report.Missing = append(report.Missing, "independent discovery progress requires a persisted assessment and database; remaining work is unknown")
		progress.RepairBlocked = true
		return progress
	}
	jobs, jobsErr := db.ResultIngestionStates(projectID, conversationID, assessmentID)
	if jobsErr != nil {
		report.Missing = append(report.Missing, "cannot read independent original ingestion state")
	}
	ingestionComplete := jobsErr == nil
	for _, job := range jobs {
		if job.State == "pending" {
			report.Missing = append(report.Missing, "original ingestion is still pending: execution:"+job.ExecutionID)
			ingestionComplete = false
		}
		if job.State == "failed" {
			report.Missing = append(report.Missing, "original ingestion failed: execution:"+job.ExecutionID+"; "+job.Reason)
			ingestionComplete = false
		}
	}
	groups, capped, groupsErr := db.AssessmentDiscoveryGroups(projectID, conversationID, assessmentID)
	if groupsErr != nil {
		report.Missing = append(report.Missing, "cannot compare independent discovery inventory")
	}
	if capped {
		report.Missing = append(report.Missing, "independent discovery comparison reached its bounded limit; completion cannot be claimed")
	}
	sources, sourcesErr := db.AssessmentReconSources(projectID, conversationID, assessmentID)
	if sourcesErr != nil {
		report.Missing = append(report.Missing, "cannot read actual reconnaissance source metadata")
	}
	index := completeCoverageSources(sources, time.Now().UnixMilli())
	originalsErr := loadHTTPOriginals(db, projectID, conversationID, assessmentID, &index)
	if originalsErr != nil {
		report.Missing = append(report.Missing, originalsErr.Error())
	}
	progress.EvidenceExecutions = len(index.byExecution)
	// Verified target-facing HTTP exchanges (e.g. the model's own
	// `curl -q -sSi` runs against assessed hosts) are auditable testing
	// progress. They renew the continuation clock; ledger writes never do.
	progress.HTTPExecutions = len(index.http)
	progress.Known = ingestionComplete && groupsErr == nil && !capped && sourcesErr == nil && originalsErr == nil
	if groupsErr == nil {
		// Do not confuse a copied endpoint+risk=N/A fact with an evidenced
		// disposition. The full independent inventory is still checked below;
		// only its displayed diagnostics are sampled, never its counts.
		dispositions := inventoryDispositionFacts(facts, assessmentID, index)
		missing := coverage.CheckBoundDiscoveryInventory(dispositions, assessmentID, groups, index.binding)
		progress.InventoryGroups = len(groups)
		progress.UnresolvedGroups = len(missing)
		progress.MappedGroups = len(groups) - len(missing)
		appendIndependentInventoryChecks(report, progress, missing)
	}
	progress.RepairBlocked = !progress.Known || progress.UnresolvedGroups > MaxAutomaticCoverageRepairGroups
	if progress.RepairBlocked {
		feedback := coverageRepairBlockedFeedback(progress)
		if progress.Known {
			// 大规模原始候选库存不再阻断交付：以明确限制披露。原始候选
			// 是工具输出的片段而不是业务单元，不要求也不允许逐 URL 记账；
			// 处置证据（基线单元+原件）仍然认可，只是不作为交付门槛。
			report.Blocked = append([]string{feedback}, report.Blocked...)
		} else {
			// 读取失败或入库未完成是真实的数据完整性缺口，保留阻断。
			report.Missing = append([]string{feedback}, report.Missing...)
		}
	}
	if sourcesErr != nil {
		return progress
	}
	for _, fact := range facts {
		if !strings.HasPrefix(fact.Key, "recon/source/") {
			continue
		}
		fields, err := coverage.ParseLedgerBody(fact.Body)
		if err != nil || fieldText(fields, "assessment_id") != assessmentID {
			continue
		}
		status := fieldText(fields, "status")
		if status == "not-applicable" {
			continue
		}
		tool := recon.CanonicalTool(fieldText(fields, "tool"))
		proof := fieldText(fields, "evidence")
		executionID := fieldText(fields, "execution_id")
		sourceID := fieldText(fields, "source_id")
		explicitBinding := sourceID != "" || executionID != ""
		matched := false
		if status == "covered" && (tool == "exec" || tool == "execute" || tool == "curl" || tool == "http-framework-test") {
			bound := make(map[string]any, len(fields)+1)
			for name, value := range fields {
				bound[name] = value
			}
			bound["endpoint_url"] = fieldText(fields, "target")
			bound["http_tool"] = tool
			matched = index.corroborates(bound)
		}
		proofReferences := referencesAnyExecution(proof, sources, tool)
		for _, source := range sources {
			if source.Tool != tool {
				continue
			}
			if explicitBinding {
				if sourceID != "" && sourceID != source.ID {
					continue
				}
				if executionID != "" && executionID != source.ExecutionID {
					continue
				}
			} else if proofReferences && !strings.Contains(proof, source.ExecutionID) {
				// 证据文本明确引用了其它执行：本执行不参与匹配。
				continue
			}
			// 没有执行绑定的“手写”来源声明按同工具的真实执行兜底：
			// covered 需要存在 parsed+complete 的执行，blocked 需要存在任意执行。
			// 系统自动登记（auto-*）仍保留为权威来源凭据；此放宽只避免模型因
			// 不知道绑定格式而陷入无法修复的永久缺口（并反复重跑工具）。
			if status == "covered" && source.State == evidence.Parsed && source.Completion == evidence.Complete && (source.ExpiresAtMS == 0 || source.ExpiresAtMS > time.Now().UnixMilli()) {
				matched = true
				break
			}
			if status == "blocked" {
				matched = true
				break
			}
		}
		if !matched {
			report.Missing = append(report.Missing, sourceClaimMissingFeedback(fact.Key, tool, sources))
		}
	}
	// Partial originals require an actual, evidenced source blocker; a manifest
	// made self-consistent by lowering counts is not a disposition.
	for _, source := range sources {
		if source.Completion == evidence.Complete && source.State == evidence.Parsed && (source.ExpiresAtMS == 0 || source.ExpiresAtMS > time.Now().UnixMilli()) {
			continue
		}
		switch source.Tool {
		case "fofa", "subfinder", "oneforall", "dnsx", "httpx", "naabu", "nmap", "gau", "katana", "jsapiscan", "jsluice", "nuclei":
		default:
			continue
		}
		blocked := false
		for _, fact := range facts {
			if !strings.HasPrefix(fact.Key, "recon/source/") {
				continue
			}
			fields, err := coverage.ParseLedgerBody(fact.Body)
			if err != nil {
				continue
			}
			if fieldText(fields, "assessment_id") == assessmentID && fieldText(fields, "status") == "blocked" && strings.Contains(fieldText(fields, "evidence"), source.ExecutionID) {
				blocked = true
				break
			}
		}
		if !blocked {
			report.Missing = append(report.Missing, "partial/unsupported source lacks an evidenced blocker: execution:"+source.ExecutionID)
		}
	}
	return progress
}

// appendIndependentInventoryChecks 把仍未处置的原始候选作为明确限制披露，
// 而不是阻断交付的缺口。原始候选是工具输出的片段，不是业务测试单元；
// 总数与来源全部保留，绝不把未测写成安全。
func appendIndependentInventoryChecks(report *coverage.Report, progress CoverageProgress, missing []string) {
	if len(missing) == 0 {
		return
	}
	label := "total"
	if !progress.Known {
		label = "observed (full total unknown)"
	}
	report.Blocked = append(report.Blocked, fmt.Sprintf("independent discovery inventory: %s=%d, mapped=%d, unresolved=%d; untested/unclassified raw candidates are disclosed as explicit limitations, not safety evidence and not a per-URL repair queue", label, progress.InventoryGroups, progress.MappedGroups, progress.UnresolvedGroups))
	if len(missing) > independentInventorySampleLimit {
		report.Blocked = append(report.Blocked, missing[:independentInventorySampleLimit]...)
		report.Blocked = append(report.Blocked, fmt.Sprintf("%d additional independent discovery groups remain unresolved; samples above are diagnostic samples, not a per-URL work queue", len(missing)-independentInventorySampleLimit))
	} else {
		report.Blocked = append(report.Blocked, missing...)
	}
}

func coverageRepairBlockedFeedback(progress CoverageProgress) string {
	detail := fmt.Sprintf("%d unresolved raw candidate groups exceed the automatic repair limit %d", progress.UnresolvedGroups, MaxAutomaticCoverageRepairGroups)
	if !progress.Known {
		detail = "independent inventory/source progress is unknown or incomplete; zero remaining work must not be inferred"
	}
	return "independent coverage inventory disclosure: " + detail + "; mechanical per-URL bookkeeping is not required and unresolved raw candidates are disclosed as explicit limitations, never as safety evidence. Continue auditable classification by authorized scope, freshness and business templates and prioritize real high-value verification; retain verified results and untested/pending-classification limitations in the final delivery. Do not generate per-URL N/A, negated or safe facts, truncate the inventory, lower totals, or skip validation to claim completion. 原始库存按未覆盖披露、不阻断交付；停止机械补写不等于停止实际测试，先分类去重、核实范围，再执行可行验证。"
}

// referencesAnyExecution 判断证据文本是否引用了同工具任一真实执行的执行 ID。
// 证据明确指向某次执行时保留严格判定；完全没有引用时，无绑定声明走
// “同工具合格执行”兜底（见 checkIndependentInventory）。
func referencesAnyExecution(proof string, sources []database.AssessmentSourceMetadata, tool string) bool {
	proof = strings.TrimSpace(proof)
	if proof == "" {
		return false
	}
	for _, source := range sources {
		if tool != "" && source.Tool != tool {
			continue
		}
		if source.ExecutionID != "" && strings.Contains(proof, source.ExecutionID) {
			return true
		}
	}
	return false
}

// sourceClaimMissingFeedback 为仍未闭合的来源声明生成可操作说明：告知该工具
// 的真实执行与解析状态，并给出可行修复方式——引用 auto-* 事实中的
// source_id/execution_id，或对解析不支持的工具改为 blocked（附 error/alt_tried），
// 而不是反复重跑工具（解析支持不会因重跑改变）。
func sourceClaimMissingFeedback(key, tool string, sources []database.AssessmentSourceMetadata) string {
	parsed, unparseable, total := 0, 0, 0
	reason := ""
	for _, source := range sources {
		if tool != "" && source.Tool != tool {
			continue
		}
		total++
		if source.State == evidence.Parsed && source.Completion == evidence.Complete {
			parsed++
			continue
		}
		unparseable++
		if source.Reason != "" {
			reason = source.Reason
		}
	}
	switch {
	case total == 0:
		return key + ": source claim has no recorded execution of " + tool + "; run the tool once, or record an evidenced blocked entry instead of a covered claim"
	case parsed > 0:
		return key + ": source claim lacks an execution binding while parsed executions of " + tool + " exist; reference the auto-* source_id/execution_id in this fact or its evidence (rerunning the tool adds nothing)"
	default:
		if reason == "" {
			reason = "unparseable_output"
		}
		return key + ": source claim cannot be satisfied because outputs of " + tool + " are not parseable (" + reason + "); record this source as blocked with error and alt_tried instead of covered — rerunning the tool will not change parser support, and system auto-* entries remain the authoritative evidence"
	}
}

func fieldText(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return strings.TrimSpace(value)
}
