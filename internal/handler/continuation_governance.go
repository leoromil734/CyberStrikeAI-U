package handler

import (
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/database"
)

// A manual continuation gets a separate run record while retaining the same
// assessment inventory and authorization. Historical batch status is immutable.
func (h *AgentHandler) beginGovernedContinuation(conversationID string) (string, error) {
	if h.db == nil {
		return "", nil
	}
	previous, err := h.db.LatestAssessmentRun(conversationID)
	if err != nil {
		return "", err
	}
	if previous == nil || previous.Mode == database.AssessmentModeLegacy || previous.Mode == database.AssessmentModeConversation {
		return "", nil
	}
	run, err := h.db.BeginAssessmentRun(conversationID, previous.ProjectID, previous.QueueID, previous.TaskID, previous.Mode, previous.AssessmentID)
	if err != nil {
		return "", err
	}
	return run.ID, nil
}
func (h *AgentHandler) finishGovernedContinuation(id, status string) {
	if h.db == nil || id == "" {
		return
	}
	outcome := agentfinalizer.Outcome(status, "", "")
	// A successful tool/model exit is not itself verified delivery.
	_, _ = h.db.Exec(`UPDATE assessment_runs SET status=?,outcome=?,completion_reason='run_ended_without_verified_delivery',ended_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'`, status, outcome, id)
}
func (h *AgentHandler) saveGovernedRunDecision(conversationID string, d agentfinalizer.Decision) {
	if h.db == nil || h.tasks == nil {
		return
	}
	task := h.tasks.GetTaskSnapshot(conversationID)
	if task == nil || task.AssessmentRunID == "" {
		return
	}
	status := d.Status
	if status == agentfinalizer.StatusInProgress {
		status = agentfinalizer.StatusBlocked
	}
	_ = h.db.FinishAssessmentRun(task.AssessmentRunID, status, d.CompletionReason, agentfinalizer.Outcome(status, d.CompletionReason, d.FinalText))
}
