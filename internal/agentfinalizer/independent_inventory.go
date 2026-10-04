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
	progress.EvidenceExecutions = len(index.byExecution)
	progress.Known = ingestionComplete && groupsErr == nil && !capped && sourcesErr == nil
	if groupsErr == nil {
		// Do not confuse a copied endpoint+risk=N/A fact with an evidenced
		// disposition. The full independent inventory is still checked below;
		// only its displayed diagnostics are sampled, never its counts.
		dispositions := inventoryDispositionFacts(facts, assessmentID, index)
		missing := coverage.CheckDiscoveryInventory(dispositions, assessmentID, groups)
		progress.InventoryGroups = len(groups)
		progress.UnresolvedGroups = len(missing)
		progress.MappedGroups = len(groups) - len(missing)
		appendIndependentInventoryChecks(report, progress, missing)
	}
	progress.RepairBlocked = !progress.Known || progress.UnresolvedGroups > MaxAutomaticCoverageRepairGroups
	if progress.RepairBlocked {
		// Put the stop instruction before sample gaps so bounded consumers do
		// not accidentally turn those samples into another repair work queue.
		report.Missing = append([]string{coverageRepairBlockedFeedback(progress)}, report.Missing...)
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
		matched := false
		for _, source := range sources {
			if source.Tool != tool {
				continue
			}
			if sourceID != "" && sourceID != source.ID {
				continue
			}
			if executionID != "" && executionID != source.ExecutionID {
				continue
			}
			if sourceID == "" && executionID == "" && !strings.Contains(proof, source.ExecutionID) {
				continue
			}
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
			report.Missing = append(report.Missing, fact.Key+": source claim has no matching actual execution/original with the required completeness")
		}
	}
	// Partial originals require an actual, evidenced source blocker; a manifest
	// made self-consistent by lowering counts is not a disposition.
	for _, source := range sources {
		if source.Completion == evidence.Complete && source.State == evidence.Parsed && (source.ExpiresAtMS == 0 || source.ExpiresAtMS > time.Now().UnixMilli()) {
			continue
		}
		switch source.Tool {
		case "fofa", "subfinder", "oneforall", "dnsx", "httpx", "naabu", "nmap", "gau", "katana", "jsapiscan", "nuclei":
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

func appendIndependentInventoryChecks(report *coverage.Report, progress CoverageProgress, missing []string) {
	if len(missing) == 0 {
		return
	}
	label := "total"
	if !progress.Known {
		label = "observed (full total unknown)"
	}
	report.Missing = append(report.Missing, fmt.Sprintf("independent discovery inventory: %s=%d, mapped=%d, unresolved=%d; raw candidates are not confirmed business test units; a URL match or N/A-only risk facts are not an evidenced disposition", label, progress.InventoryGroups, progress.MappedGroups, progress.UnresolvedGroups))
	if len(missing) > independentInventorySampleLimit {
		report.Missing = append(report.Missing, missing[:independentInventorySampleLimit]...)
		report.Missing = append(report.Missing, fmt.Sprintf("%d additional independent discovery groups lack evidenced dispositions; the displayed groups are diagnostic samples, not a per-URL repair queue", len(missing)-independentInventorySampleLimit))
	} else {
		report.Missing = append(report.Missing, missing...)
	}
}

func coverageRepairBlockedFeedback(progress CoverageProgress) string {
	detail := fmt.Sprintf("%d unresolved raw candidate groups exceed the automatic repair limit %d", progress.UnresolvedGroups, MaxAutomaticCoverageRepairGroups)
	if !progress.Known {
		detail = "independent inventory/source progress is unknown or incomplete; zero remaining work must not be inferred"
	}
	return "automatic coverage repair blocked: " + detail + "; return currently verified results and explicit untested/pending-classification limitations. First perform auditable screening by authorized scope, freshness and business templates while retaining original inventory totals and provenance. Do not generate per-URL N/A, negated or safe facts, truncate the inventory, lower totals, or skip validation to claim completion. 当前仅返回已验证成果及未测/待分类限制；先按授权范围、当前性和业务模板进行可审计筛选，禁止逐URL生成N/A、否定或安全结论。"
}

func fieldText(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return strings.TrimSpace(value)
}
