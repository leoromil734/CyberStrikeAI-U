package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	AssessmentModeLegacy        = "legacy"
	AssessmentModeConversation  = "conversation"
	AssessmentModeExecution     = "execution"
	AssessmentModeComprehensive = "comprehensive"
)

func NormalizeAssessmentMode(mode string, projectBound bool) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		if projectBound {
			return AssessmentModeComprehensive, nil
		}
		return AssessmentModeExecution, nil
	case AssessmentModeConversation, AssessmentModeExecution, AssessmentModeComprehensive:
		return strings.ToLower(strings.TrimSpace(mode)), nil
	default:
		return "", fmt.Errorf("assessmentMode must be auto, conversation, execution or comprehensive")
	}
}

// Governance is additive: old batch rows, assistant text and findings are never
// rewritten to fabricate a new completion or verification result.
func (db *DB) initTaskGovernanceTables() error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS batch_queue_policies (
			queue_id TEXT PRIMARY KEY, assessment_mode TEXT NOT NULL,
			duplicate_tasks_skipped INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			FOREIGN KEY(queue_id) REFERENCES batch_task_queues(id) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS assessment_runs (
			id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, project_id TEXT,
			queue_id TEXT, task_id TEXT, assessment_id TEXT NOT NULL DEFAULT '',
			assessment_mode TEXT NOT NULL, status TEXT NOT NULL, completion_reason TEXT NOT NULL DEFAULT '',
			outcome TEXT NOT NULL DEFAULT '', started_at DATETIME NOT NULL, ended_at DATETIME,
			FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE)`,
		`CREATE INDEX IF NOT EXISTS idx_assessment_runs_conversation ON assessment_runs(conversation_id, started_at)`,
		`CREATE INDEX IF NOT EXISTS idx_assessment_runs_task ON assessment_runs(queue_id, task_id, started_at)`,
	} {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func saveBatchQueuePolicyTx(tx *Tx, queueID, mode string, skipped int, at time.Time) error {
	if strings.TrimSpace(mode) == "" {
		return nil
	} // legacy API compatibility
	_, err := tx.Exec(`INSERT INTO batch_queue_policies(queue_id,assessment_mode,duplicate_tasks_skipped,created_at)
		VALUES(?,?,?,?) ON CONFLICT(queue_id) DO UPDATE SET assessment_mode=excluded.assessment_mode,
		duplicate_tasks_skipped=excluded.duplicate_tasks_skipped`, queueID, mode, skipped, at)
	return err
}

func (db *DB) GetBatchQueuePolicy(queueID string) (string, int, error) {
	mode, skipped := AssessmentModeLegacy, 0
	err := db.QueryRow(`SELECT assessment_mode,duplicate_tasks_skipped FROM batch_queue_policies WHERE queue_id=?`, queueID).Scan(&mode, &skipped)
	if err == sql.ErrNoRows {
		return AssessmentModeLegacy, 0, nil
	}
	return mode, skipped, err
}

type AssessmentRun struct {
	ID               string    `json:"runId"`
	ConversationID   string    `json:"conversationId"`
	ProjectID        string    `json:"projectId,omitempty"`
	QueueID          string    `json:"queueId,omitempty"`
	TaskID           string    `json:"taskId,omitempty"`
	AssessmentID     string    `json:"assessmentId,omitempty"`
	Mode             string    `json:"assessmentMode"`
	Status           string    `json:"status"`
	CompletionReason string    `json:"completionReason,omitempty"`
	Outcome          string    `json:"outcome,omitempty"`
	StartedAt        time.Time `json:"startedAt"`
}

func (db *DB) BeginAssessmentRun(conversationID, projectID, queueID, taskID, mode, assessmentID string) (*AssessmentRun, error) {
	if conversationID == "" {
		return nil, fmt.Errorf("conversation is required")
	}
	if mode == AssessmentModeComprehensive && projectID == "" {
		return nil, fmt.Errorf("comprehensive assessment requires a bound project")
	}
	r := &AssessmentRun{ID: uuid.NewString(), ConversationID: conversationID, ProjectID: projectID,
		QueueID: queueID, TaskID: taskID, Mode: mode, AssessmentID: assessmentID, Status: "running", StartedAt: time.Now()}
	_, err := db.Exec(`INSERT INTO assessment_runs(id,conversation_id,project_id,queue_id,task_id,assessment_id,assessment_mode,status,started_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, r.ID, conversationID, nullIfEmpty(projectID), nullIfEmpty(queueID), nullIfEmpty(taskID), assessmentID, mode, r.Status, r.StartedAt)
	return r, err
}

func (db *DB) LatestAssessmentRun(conversationID string) (*AssessmentRun, error) {
	r := &AssessmentRun{}
	err := db.QueryRow(`SELECT id,conversation_id,COALESCE(project_id,''),COALESCE(queue_id,''),COALESCE(task_id,''),
		assessment_id,assessment_mode,status,completion_reason,outcome,started_at FROM assessment_runs
		WHERE conversation_id=? ORDER BY started_at DESC,id DESC LIMIT 1`, conversationID).
		Scan(&r.ID, &r.ConversationID, &r.ProjectID, &r.QueueID, &r.TaskID, &r.AssessmentID, &r.Mode, &r.Status, &r.CompletionReason, &r.Outcome, &r.StartedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (db *DB) FinishAssessmentRun(id, status, reason, outcome string) error {
	if id == "" {
		return nil
	}
	_, err := db.Exec(`UPDATE assessment_runs SET status=?,completion_reason=?,outcome=?,ended_at=? WHERE id=?`, status, reason, outcome, time.Now(), id)
	return err
}
