package agentfinalizer

import (
	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
	"fmt"
	"strings"
	"time"
)

func checkIndependentInventory(db *database.DB, projectID, conversationID, assessmentID string, facts []coverage.Fact, report *coverage.Report) {
	jobs, err := db.ResultIngestionStates(projectID, conversationID, assessmentID)
	if err != nil {
		report.Missing = append(report.Missing, "cannot read independent original ingestion state")
		return
	}
	for _, job := range jobs {
		if job.State == "pending" {
			report.Missing = append(report.Missing, "original ingestion is still pending: execution:"+job.ExecutionID)
		}
		if job.State == "failed" {
			report.Missing = append(report.Missing, "original ingestion failed: execution:"+job.ExecutionID+"; "+job.Reason)
		}
	}
	groups, capped, err := db.AssessmentDiscoveryGroups(projectID, conversationID, assessmentID)
	if err != nil {
		report.Missing = append(report.Missing, "cannot compare independent discovery inventory")
		return
	}
	missing := coverage.CheckDiscoveryInventory(facts, assessmentID, groups)
	if len(missing) > 30 {
		report.Missing = append(report.Missing, missing[:30]...)
		report.Missing = append(report.Missing, fmt.Sprintf("%d additional independent discovery groups lack dispositions; query inventory in pages", len(missing)-30))
	} else {
		report.Missing = append(report.Missing, missing...)
	}
	if capped {
		report.Missing = append(report.Missing, "independent discovery comparison reached its bounded limit; completion cannot be claimed")
	}
	sources, err := db.AssessmentReconSources(projectID, conversationID, assessmentID)
	if err != nil {
		report.Missing = append(report.Missing, "cannot read actual reconnaissance source metadata")
		return
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
}
func fieldText(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return strings.TrimSpace(value)
}
