package database

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/targets"

	"github.com/google/uuid"
)

// BatchQueueCreateOptions adds opt-in project isolation without changing the
// existing shared-project behaviour of API clients or persisted queues.
type BatchQueueCreateOptions struct {
	IndependentProjects bool
	OwnerUserID         string
}

// NewBatchTaskProject allocates a private project identity before persistence.
// Extracted hostnames are display metadata only: normalized domains must never
// replace the original task's URL/path/port restrictions as authorized scope.
func NewBatchTaskProject(message string) *Project {
	id := uuid.New().String()
	return &Project{
		ID: id, Name: BatchTaskProjectName(message, id), Status: "active",
		Description: "批量任务独立项目；仅使用本条任务的原始目标与范围，不共享其他任务事实。",
	}
}

func BatchTaskProjectName(message, projectID string) string {
	primary := "task"
	if extracted := targets.Extract(message); len(extracted) > 0 {
		primary = extracted[0]
	}
	if utf8.RuneCountInString(primary) > 180 {
		primary = string([]rune(primary)[:180])
	}
	suffix := strings.ReplaceAll(projectID, "-", "")
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	return primary + "-" + suffix
}

func insertBatchTaskProjectTx(tx *Tx, project *Project, ownerUserID string, at time.Time) error {
	if project == nil || strings.TrimSpace(project.ID) == "" {
		return fmt.Errorf("独立任务缺少项目标识")
	}
	_, err := tx.Exec(`INSERT INTO projects
		(id, name, description, scope_json, status, pinned, created_at, updated_at, owner_user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		project.ID, project.Name, project.Description, project.ScopeJSON, "active", 0, at, at, nullIfEmpty(strings.TrimSpace(ownerUserID)))
	if err != nil {
		return fmt.Errorf("创建任务独立项目失败: %w", err)
	}
	return assignBatchResourceTx(tx, ownerUserID, "project", project.ID, at)
}

func assignBatchResourceTx(tx *Tx, ownerUserID, resourceType, resourceID string, at time.Time) error {
	ownerUserID = strings.TrimSpace(ownerUserID)
	if ownerUserID == "" {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO rbac_resource_assignments (id, user_id, resource_type, resource_id, created_at)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, resource_type, resource_id) DO NOTHING`,
		uuid.New().String(), ownerUserID, resourceType, resourceID, at)
	if err != nil {
		return fmt.Errorf("分配任务资源权限失败: %w", err)
	}
	return nil
}

// AddBatchTaskWithProject atomically persists a new task, its optional private
// project and its submitted targets. It never starts or resumes the queue.
func (db *DB) AddBatchTaskWithProject(queueID, taskID, message, aiChannelID string, project *Project) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner string
	var queueProject *string
	var independent int
	if err := tx.QueryRow(`SELECT COALESCE(owner_user_id,''), project_id, independent_projects FROM batch_task_queues WHERE id = ?`, queueID).Scan(&owner, &queueProject, &independent); err != nil {
		return fmt.Errorf("读取队列项目配置失败: %w", err)
	}
	if independent != 0 && project == nil {
		return fmt.Errorf("独立项目队列的新任务必须创建独立项目")
	}
	at := time.Now()
	projectID := stringFromNull(queueProject)
	if project != nil {
		if independent == 0 {
			return fmt.Errorf("共享项目队列不能写入独立任务项目")
		}
		if err := insertBatchTaskProjectTx(tx, project, owner, at); err != nil {
			return err
		}
		projectID = project.ID
	}
	persistedProjectID := ""
	if project != nil {
		persistedProjectID = project.ID
	}
	if _, err := tx.Exec(`INSERT INTO batch_tasks (id, queue_id, message, ai_channel_id, retry_count, status, project_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, taskID, queueID, message, strings.TrimSpace(aiChannelID), 0, "pending", nullIfEmpty(persistedProjectID)); err != nil {
		return fmt.Errorf("添加批量任务失败: %w", err)
	}
	if _, err := RecordTaskTargetsTx(tx, queueID, taskID, message, projectID, owner, at); err != nil {
		return fmt.Errorf("登记任务目标失败: %w", err)
	}
	return tx.Commit()
}

// UpdateBatchTaskMessageWithProject retains existing execution history. When
// the caller allocates a replacement project, only future runs use it; past
// conversations and their facts are deliberately not moved or rewritten.
func (db *DB) UpdateBatchTaskMessageWithProject(queueID, taskID, message string, project *Project) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner, projectID string
	var independent int
	if err := tx.QueryRow(`SELECT COALESCE(q.owner_user_id,''), COALESCE(bt.project_id,q.project_id,''), q.independent_projects
		FROM batch_tasks bt JOIN batch_task_queues q ON q.id=bt.queue_id
		WHERE bt.queue_id=? AND bt.id=?`, queueID, taskID).Scan(&owner, &projectID, &independent); err != nil {
		return fmt.Errorf("读取任务项目配置失败: %w", err)
	}
	if project != nil {
		if independent == 0 {
			return fmt.Errorf("共享项目队列不能替换为独立任务项目")
		}
		if err := insertBatchTaskProjectTx(tx, project, owner, time.Now()); err != nil {
			return err
		}
		projectID = project.ID
		if _, err := tx.Exec(`UPDATE batch_tasks SET message=?, project_id=?, status='pending', conversation_id=NULL, started_at=NULL, completed_at=NULL, error=NULL, result=NULL, retry_count=0 WHERE queue_id=? AND id=?`, message, projectID, queueID, taskID); err != nil {
			return err
		}
	} else if _, err := tx.Exec(`UPDATE batch_tasks SET message=? WHERE queue_id=? AND id=?`, message, queueID, taskID); err != nil {
		return err
	}
	if _, err := RecordTaskTargetsTx(tx, queueID, taskID, message, projectID, owner, time.Now()); err != nil {
		return fmt.Errorf("登记编辑后的任务目标失败: %w", err)
	}
	return tx.Commit()
}
