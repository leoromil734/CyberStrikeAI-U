package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/targets"
)

const targetHistoryBatchSize = 250

// initTaskTargetHistory 创建独立的任务提交历史，不改变实际运行次数。
// 在现有目标表建好后调用；不依赖队列 project_mode 或任务 project_id 列。
func (db *DB) initTaskTargetHistory() error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS task_target_registrations (
			target TEXT NOT NULL,
			queue_id TEXT NOT NULL,
			task_id TEXT NOT NULL,
			task_title TEXT NOT NULL DEFAULT '',
			project_id TEXT NOT NULL DEFAULT '',
			owner_user_id TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			PRIMARY KEY (target, queue_id, task_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_task_target_owner ON task_target_registrations(owner_user_id, target)`,
		`CREATE INDEX IF NOT EXISTS idx_task_target_queue ON task_target_registrations(queue_id, task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_task_target_project ON task_target_registrations(project_id, target)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_first_user ON messages(conversation_id, role, created_at, id)`,
	} {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("初始化任务目标历史失败: %w", err)
		}
	}
	// 运行明细保留归属快照；删除对话后也不把私人目标暴露给其他用户。
	hasOwner, err := db.columnExists("target_run_events", "owner_user_id")
	if err != nil {
		return err
	}
	if !hasOwner {
		if _, err := db.Exec(`ALTER TABLE target_run_events ADD COLUMN owner_user_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("添加目标运行归属失败: %w", err)
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_target_run_events_owner ON target_run_events(owner_user_id, target)`)
	return err
}

// RecordTaskTargetsTx 只从完整原始任务输入提取目标，按 (target, queueID, taskID) 幂等登记。
// 编辑为新目标会增加历史登记，旧的提交历史仍保留；不修改 target_runs/run_count。
// 调用方负责在创建、追加、编辑任务的同一事务内调用并处理错误。
func RecordTaskTargetsTx(tx *Tx, queueID, taskID, message, projectID, ownerUserID string, at time.Time) (int, error) {
	if tx == nil || tx.Tx == nil {
		return 0, fmt.Errorf("任务目标登记需要有效事务")
	}
	queueID, taskID = strings.TrimSpace(queueID), strings.TrimSpace(taskID)
	if queueID == "" || taskID == "" {
		return 0, fmt.Errorf("任务目标登记需要队列和任务 ID")
	}
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	title := []rune(strings.TrimSpace(message))
	if len(title) > 100 {
		title = title[:100]
	}
	recorded := 0
	for _, target := range targets.Extract(message) {
		res, err := tx.Exec(`INSERT INTO task_target_registrations
			(target, queue_id, task_id, task_title, project_id, owner_user_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(target, queue_id, task_id) DO NOTHING`,
			target, queueID, taskID, string(title), strings.TrimSpace(projectID), strings.TrimSpace(ownerUserID), at)
		if err != nil {
			return recorded, fmt.Errorf("登记任务目标失败: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return recorded, err
		}
		recorded += int(n)
	}
	return recorded, nil
}

// RecordTaskTargets 是登记任务目标的便捷事务包装。
func (db *DB) RecordTaskTargets(queueID, taskID, message, projectID, ownerUserID string, at time.Time) (int, error) {
	if db == nil {
		return 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n, err := RecordTaskTargetsTx(tx, queueID, taskID, message, projectID, ownerUserID, at)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// BackfillTaskTargetRegistrations 分批读取已有任务的完整 message，并返回新登记行数。
// 只读原始输入，不读取助手、角色模板、结果或日志；重跑不会增加计数。
func (db *DB) BackfillTaskTargetRegistrations() (int, error) {
	if db == nil {
		return 0, nil
	}
	projectExpr := `COALESCE(NULLIF(c.project_id, ''), q.project_id, '')`
	hasTaskProject, err := db.columnExists("batch_tasks", "project_id")
	if err != nil {
		return 0, err
	}
	if hasTaskProject {
		projectExpr = `COALESCE(NULLIF(t.project_id, ''), NULLIF(c.project_id, ''), q.project_id, '')`
	}
	createdExpr := "q.created_at"
	hasTaskCreated, err := db.columnExists("batch_tasks", "created_at")
	if err != nil {
		return 0, err
	}
	if hasTaskCreated {
		createdExpr = "COALESCE(t.created_at, q.created_at)"
	}
	inserted, cursor := 0, ""
	for {
		rows, err := db.Query(`SELECT t.id, t.queue_id, t.message, `+projectExpr+`,
			COALESCE(NULLIF(q.owner_user_id, ''), NULLIF(c.owner_user_id, ''), p.owner_user_id, ''), `+createdExpr+`
			FROM batch_tasks t JOIN batch_task_queues q ON q.id = t.queue_id
			LEFT JOIN conversations c ON c.id = t.conversation_id
			LEFT JOIN projects p ON p.id = `+projectExpr+`
			WHERE t.id > ? ORDER BY t.id LIMIT ?`, cursor, targetHistoryBatchSize)
		if err != nil {
			return inserted, fmt.Errorf("读取历史任务失败: %w", err)
		}
		type taskInput struct {
			id, queue, message, project, owner string
			created                            time.Time
		}
		batch := make([]taskInput, 0, targetHistoryBatchSize)
		for rows.Next() {
			var item taskInput
			var created sql.NullString
			if err := rows.Scan(&item.id, &item.queue, &item.message, &item.project, &item.owner, &created); err != nil {
				rows.Close()
				return inserted, err
			}
			item.created = parseDBTime(created.String)
			batch = append(batch, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return inserted, err
		}
		if len(batch) == 0 {
			return inserted, nil
		}
		tx, err := db.Begin()
		if err != nil {
			return inserted, err
		}
		batchInserted := 0
		for _, item := range batch {
			n, err := RecordTaskTargetsTx(tx, item.queue, item.id, item.message, item.project, item.owner, item.created)
			if err != nil {
				tx.Rollback()
				return inserted, err
			}
			batchInserted += n
		}
		if err := tx.Commit(); err != nil {
			return inserted, err
		}
		inserted += batchInserted
		cursor = batch[len(batch)-1].id
	}
}

// conversationOriginalTargetInputSQL 优先已关联批量任务的完整输入，再取最早用户输入。
// 有原始输入但没有域名时，绝不退回标题，避免从改名标题/助手内容采集噪声。
const conversationOriginalTargetInputSQL = `COALESCE(
	(SELECT t.message FROM batch_tasks t WHERE t.conversation_id = c.id AND TRIM(t.message) <> '' ORDER BY t.id LIMIT 1),
	(SELECT m.content FROM messages m WHERE m.conversation_id = c.id AND m.role = 'user' ORDER BY m.created_at, m.id LIMIT 1)
)`

// ConversationOriginalTargetInput 不加载会话消息列表，仅返回目标登记所需原始输入。
func (db *DB) ConversationOriginalTargetInput(conversationID string) (message string, found bool, err error) {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return "", false, nil
	}
	var input sql.NullString
	err = db.QueryRow(`SELECT `+conversationOriginalTargetInputSQL+` FROM conversations c WHERE c.id = ?`, conversationID).Scan(&input)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return input.String, input.Valid, err
}

// ConversationTaskTargetInput 读取关联批量任务的完整原始输入。
// 普通聊天返回 found=false，让运行登记继续使用本轮原始 req.Message。
func (db *DB) ConversationTaskTargetInput(conversationID string) (message string, found bool, err error) {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return "", false, nil
	}
	err = db.QueryRow(`SELECT message FROM batch_tasks WHERE conversation_id = ? ORDER BY id LIMIT 1`,
		strings.TrimSpace(conversationID)).Scan(&message)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return message, err == nil, err
}
