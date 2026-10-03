package agentfinalizer

import (
	"cyberstrike-ai/internal/database"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var findingReference = regexp.MustCompile(`(?i)(?:finding|vulnerability|漏洞)\s*(?:id|编号)?\s*[:：=]\s*([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
var confirmedCount = regexp.MustCompile(`(?i)(?:已确认漏洞|已验证漏洞|正式漏洞|confirmed findings)\s*(?:数|数量|总数|条数)?\s*[:：=]?\s*\*{0,2}(\d{1,5})\*{0,2}`)

// Only new governed assessments opt into the report/finding consistency gate.
// Existing saved findings and historical replies are never silently rewritten.
func reportFindingChecks(db *database.DB, in Input) []string {
	if db == nil || in.ConversationID == "" {
		return nil
	}
	run, err := db.LatestAssessmentRun(in.ConversationID)
	if err != nil || run == nil || run.Mode != database.AssessmentModeComprehensive || run.AssessmentID == "" {
		return nil
	}
	rows, err := db.Query(`SELECT id FROM vulnerabilities WHERE conversation_id=? AND project_id=? AND status NOT IN ('false_positive','ignored') AND created_at >= (SELECT MIN(started_at) FROM assessment_runs WHERE conversation_id=? AND assessment_id=?) ORDER BY id`, in.ConversationID, run.ProjectID, in.ConversationID, run.AssessmentID)
	if err != nil {
		return []string{"cannot reconcile final report with persisted formal findings"}
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return []string{"cannot read formal finding IDs"}
		}
		ids = append(ids, id)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return []string{"cannot read formal finding IDs"}
	}
	problems := []string{}
	for _, id := range ids {
		if !strings.Contains(in.Response, id) {
			problems = append(problems, "final report must list newly recorded formal finding ID: "+id)
		}
	}
	for _, match := range findingReference.FindAllStringSubmatch(in.Response, 100) {
		v, err := db.GetVulnerability(match[1])
		if err != nil || v == nil || v.ProjectID != run.ProjectID || v.Status == "false_positive" || v.Status == "ignored" {
			problems = append(problems, "final report references an absent/non-formal/out-of-project finding: "+match[1])
		}
	}
	// Explicit counts refer to newly recorded findings, not candidate hits. A
	// historical or project-total count must be labelled separately in prose.
	for _, match := range confirmedCount.FindAllStringSubmatch(in.Response, 10) {
		n, _ := strconv.Atoi(match[1])
		if n != len(ids) {
			problems = append(problems, fmt.Sprintf("confirmed finding count %d differs from %d persisted findings in this assessment; candidates/observations stay separate", n, len(ids)))
		}
	}
	if len(problems) > 30 {
		problems = append(problems[:30], "additional report/finding inconsistencies require reconciliation")
	}
	return problems
}
