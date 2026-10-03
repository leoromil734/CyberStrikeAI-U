package agentfinalizer

import (
	"fmt"
	"strings"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
)

// coverageForDelivery checks only a manifest written in this assistant turn,
// unless the caller explicitly requires coverage. It neither guesses intent from
// prose nor lets another conversation's project facts satisfy this assessment.
func coverageForDelivery(db *database.DB, in Input) coverage.Report {
	failure := func(message string) coverage.Report { return coverage.Report{Active: true, Missing: []string{message}} }
	if db == nil || strings.TrimSpace(in.ConversationID) == "" {
		if in.RequireCoverageEvidence {
			return failure("coverage requires a persisted conversation bound to a project")
		}
		return coverage.Report{}
	}
	if !in.RequireCoverageEvidence {
		if strings.TrimSpace(in.AssistantMessageID) == "" {
			return coverage.Report{}
		}
		var count int
		err := db.QueryRow(`SELECT COUNT(*) FROM project_facts f
			WHERE f.source_conversation_id = ? AND f.confidence != 'deprecated'
			AND f.fact_key LIKE 'recon/assessment/%'
			AND f.updated_at >= (SELECT created_at FROM messages WHERE id = ? AND conversation_id = ?)`,
			in.ConversationID, in.AssistantMessageID, in.ConversationID).Scan(&count)
		if err != nil {
			return failure(fmt.Sprintf("cannot query current assessment manifest: %v", err))
		}
		if count == 0 {
			return coverage.Report{}
		}
	}
	projectID, err := db.GetConversationProjectID(in.ConversationID)
	if err != nil || projectID == "" {
		return failure("coverage requires this conversation to be bound to a project")
	}
	facts, err := db.ListProjectCoverageFacts(projectID, in.ConversationID)
	if err != nil {
		return failure(fmt.Sprintf("cannot read coverage ledger: %v", err))
	}
	var newest *database.ProjectFact
	activeRun, runErr := db.LatestAssessmentRun(in.ConversationID)
	if runErr != nil {
		return failure("cannot read persisted assessment policy")
	}
	lockedAssessment := ""
	if activeRun != nil && activeRun.Mode == database.AssessmentModeComprehensive {
		if activeRun.ProjectID != projectID {
			return failure("assessment project binding changed; a new authorized assessment is required")
		}
		lockedAssessment = activeRun.AssessmentID
	}
	for _, fact := range facts {
		if lockedAssessment != "" && fact.FactKey != "recon/assessment/"+lockedAssessment {
			continue
		}
		if fact.SourceConversationID == in.ConversationID && strings.HasPrefix(fact.FactKey, "recon/assessment/") && (newest == nil || fact.UpdatedAt.After(newest.UpdatedAt)) {
			newest = fact
		}
	}
	if newest == nil {
		return coverage.Check(nil, true)
	}
	selected := make([]coverage.Fact, 0, len(facts))
	for _, fact := range facts {
		if fact.SourceConversationID != in.ConversationID {
			continue
		}
		if strings.HasPrefix(fact.FactKey, "recon/assessment/") && fact.FactKey != newest.FactKey {
			continue
		}
		selected = append(selected, coverage.Fact{Key: fact.FactKey, Body: fact.Body})
	}
	// Once a manifest activated the gate, an invalid mode/body cannot disable it.
	report := coverage.Check(selected, true)
	if lockedAssessment != "" {
		checkIndependentInventory(db, projectID, in.ConversationID, lockedAssessment, selected, &report)
	}
	return report
}
