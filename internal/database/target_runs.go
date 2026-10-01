package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"cyberstrike-ai/internal/targets"
)

// TargetRun 合并实际运行与任务提交历史。RunCount 按对话去重，SubmittedCount 按任务去重。
// 仅提交尚未执行的目标 RunCount 为 0，运行时间与对话指针为空。
type TargetRun struct {
	Target                 string     `json:"target"`
	RunCount               int        `json:"runCount"`
	FirstRunAt             *time.Time `json:"firstRunAt,omitempty"`
	LastRunAt              *time.Time `json:"lastRunAt,omitempty"`
	LastConversationID     string     `json:"lastConversationId,omitempty"`
	LastConversationTitle  string     `json:"lastConversationTitle,omitempty"`
	LastProjectID          string     `json:"lastProjectId,omitempty"`
	SubmittedCount         int        `json:"submittedCount"`
	LastSubmittedAt        *time.Time `json:"lastSubmittedAt,omitempty"`
	LastQueueID            string     `json:"lastQueueId,omitempty"`
	LastTaskID             string     `json:"lastTaskId,omitempty"`
	LastTaskTitle          string     `json:"lastTaskTitle,omitempty"`
	LastSubmittedProjectID string     `json:"lastSubmittedProjectId,omitempty"`
}

// TargetRunEvent 是一次「某对话跑了某目标」的明细，不包含待执行提交。
type TargetRunEvent struct {
	ID                string    `json:"id"`
	Target            string    `json:"target"`
	ConversationID    string    `json:"conversationId"`
	ConversationTitle string    `json:"conversationTitle,omitempty"`
	ProjectID         string    `json:"projectId,omitempty"`
	StartedAt         time.Time `json:"startedAt"`
}

// TargetBackfillResult 汇总一次历史运行回填的结果。
type TargetBackfillResult struct {
	Conversations  int `json:"conversations"`
	WithTargets    int `json:"withTargets"`
	EventsInserted int `json:"eventsInserted"`
	Targets        int `json:"targets"`
}

const insertTargetRunEventSQL = `
	INSERT INTO target_run_events
		(id, target, conversation_id, conversation_title, project_id, started_at, owner_user_id)
	VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT owner_user_id FROM conversations WHERE id = ?), ''))
	ON CONFLICT(target, conversation_id) DO NOTHING`

const upsertTargetRunSQL = `
	INSERT INTO target_runs
		(target, run_count, first_run_at, last_run_at, last_conversation_id, last_conversation_title, last_project_id, updated_at)
	VALUES (?, 1, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(target) DO UPDATE SET
		run_count = target_runs.run_count + 1,
		first_run_at = CASE WHEN target_runs.first_run_at IS NULL OR excluded.first_run_at < target_runs.first_run_at THEN excluded.first_run_at ELSE target_runs.first_run_at END,
		last_run_at = CASE WHEN excluded.last_run_at >= target_runs.last_run_at THEN excluded.last_run_at ELSE target_runs.last_run_at END,
		last_conversation_id = CASE WHEN excluded.last_run_at >= target_runs.last_run_at THEN excluded.last_conversation_id ELSE target_runs.last_conversation_id END,
		last_conversation_title = CASE WHEN excluded.last_run_at >= target_runs.last_run_at THEN excluded.last_conversation_title ELSE target_runs.last_conversation_title END,
		last_project_id = CASE WHEN excluded.last_run_at >= target_runs.last_run_at THEN excluded.last_project_id ELSE target_runs.last_project_id END,
		updated_at = excluded.updated_at`

// RecordTargetRuns 按 (目标, 对话) 幂等登记实际运行，不被任务提交影响。
func (db *DB) RecordTargetRuns(conversationID, conversationTitle, projectID string, list []string, at time.Time) (int, error) {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return 0, nil
	}
	conversationID = strings.TrimSpace(conversationID)
	normalized := targets.NormalizeAll(list)
	if len(normalized) == 0 {
		return 0, nil
	}
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("登记目标运行失败: %w", err)
	}
	defer tx.Rollback()
	recorded := 0
	for _, target := range normalized {
		res, err := tx.Exec(insertTargetRunEventSQL, uuid.New().String(), target, conversationID,
			strings.TrimSpace(conversationTitle), strings.TrimSpace(projectID), at, conversationID)
		if err != nil {
			return 0, fmt.Errorf("登记目标运行明细失败: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if affected == 0 {
			continue
		}
		if _, err := tx.Exec(upsertTargetRunSQL, target, at, at, conversationID, strings.TrimSpace(conversationTitle), strings.TrimSpace(projectID), at); err != nil {
			return 0, fmt.Errorf("更新目标聚合失败: %w", err)
		}
		recorded++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("登记目标运行失败: %w", err)
	}
	return recorded, nil
}

// CheckTargetRuns 查询已提交或已运行目标，兼容内部全局调用。
func (db *DB) CheckTargetRuns(list []string) ([]TargetRun, error) {
	return db.CheckTargetRunsForAccess(list, "", RBACScopeAll)
}

// CheckTargetRunsForAccess 同用户跨项目可查重，但只汇总当前用户有权限的明细。
func (db *DB) CheckTargetRunsForAccess(list []string, userID, scope string) ([]TargetRun, error) {
	if db == nil {
		return nil, nil
	}
	normalized := targets.NormalizeAll(list)
	if len(normalized) == 0 {
		return []TargetRun{}, nil
	}
	// 分块限制绑定参数数量（SQLite 同样适用），每块查询两个表，不做逐域名查询。
	out := make([]TargetRun, 0, len(normalized))
	for start := 0; start < len(normalized); start += targetHistoryBatchSize {
		end := start + targetHistoryBatchSize
		if end > len(normalized) {
			end = len(normalized)
		}
		args := make([]interface{}, 0, end-start)
		for _, target := range normalized[start:end] {
			args = append(args, target)
		}
		filter := " AND target IN (" + strings.TrimRight(strings.Repeat("?,", len(args)), ",") + ")"
		query, queryArgs := targetHistorySourcesSQL(filter, args, userID, scope)
		batch, err := db.queryTargetHistory(query+targetHistoryMergedSQL+" ORDER BY a.target", queryArgs, len(args))
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	return out, nil
}

func (db *DB) ListTargetRuns(keyword string, limit, offset int) ([]TargetRun, int, error) {
	return db.ListTargetRunsForAccess(keyword, limit, offset, "", RBACScopeAll)
}

// ListTargetRunsForAccess 在数据库内分页汇总，最近时间取提交与运行时间中较新的一个。
func (db *DB) ListTargetRunsForAccess(keyword string, limit, offset int, userID, scope string) ([]TargetRun, int, error) {
	if db == nil {
		return nil, 0, nil
	}
	limit, offset = targetHistoryPage(limit, offset)
	filter := ""
	args := []interface{}{}
	if keyword = strings.ToLower(strings.TrimSpace(keyword)); keyword != "" {
		filter = " AND target LIKE ?"
		args = append(args, "%"+keyword+"%")
	}
	query, args := targetHistorySourcesSQL(filter, args, userID, scope)
	var total int
	if err := db.QueryRow(query+` SELECT COUNT(*) FROM (SELECT target FROM run_rows UNION SELECT target FROM submission_rows) history_targets`, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计目标历史失败: %w", err)
	}
	query += targetHistoryMergedSQL + ` ORDER BY CASE
		WHEN r.last_run_at IS NULL THEN s.last_submitted_at
		WHEN s.last_submitted_at IS NULL OR r.last_run_at >= s.last_submitted_at THEN r.last_run_at
		ELSE s.last_submitted_at END DESC, a.target ASC LIMIT ? OFFSET ?`
	list, err := db.queryTargetHistory(query, append(args, limit, offset), limit)
	return list, total, err
}

func targetHistoryPage(limit, offset int) (int, int) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (db *DB) ListTargetRunEvents(target string, limit, offset int) ([]TargetRunEvent, int, error) {
	return db.ListTargetRunEventsForAccess(target, limit, offset, "", RBACScopeAll)
}

func (db *DB) ListTargetRunEventsForAccess(target string, limit, offset int, userID, scope string) ([]TargetRunEvent, int, error) {
	if db == nil || targets.Normalize(target) == "" {
		return nil, 0, nil
	}
	target = targets.Normalize(target)
	limit, offset = targetHistoryPage(limit, offset)
	access, args := targetHistoryAccessSQL("e", "conversation", "conversation_id", userID, scope)
	args = append([]interface{}{target}, args...)
	from := " FROM target_run_events e WHERE target = ?" + access
	var total int
	if err := db.QueryRow("SELECT COUNT(*)"+from, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计目标运行明细失败: %w", err)
	}
	rows, err := db.Query(`SELECT e.id, e.target, e.conversation_id, e.conversation_title, e.project_id, e.started_at`+from+`
		ORDER BY e.started_at DESC, e.id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询目标运行明细失败: %w", err)
	}
	defer rows.Close()
	out := make([]TargetRunEvent, 0, limit)
	for rows.Next() {
		var item TargetRunEvent
		var title, projectID *string
		if err := rows.Scan(&item.ID, &item.Target, &item.ConversationID, &title, &projectID, &item.StartedAt); err != nil {
			return nil, 0, fmt.Errorf("扫描目标运行明细失败: %w", err)
		}
		item.ConversationTitle, item.ProjectID = stringFromNull(title), stringFromNull(projectID)
		out = append(out, item)
	}
	return out, total, rows.Err()
}

func (db *DB) DeleteTargetRun(target string) error {
	return db.DeleteTargetRunForAccess(target, "", RBACScopeAll)
}

// DeleteTargetRunForAccess 只删除可访问的运行/提交明细，保留其他用户历史并同步重算该目标。
func (db *DB) DeleteTargetRunForAccess(target, userID, scope string) error {
	if db == nil {
		return nil
	}
	target = targets.Normalize(target)
	if target == "" {
		return fmt.Errorf("目标不能为空")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, entry := range []struct{ table, alias, resource, column string }{
		{"target_run_events", "e", "conversation", "conversation_id"},
		{"task_target_registrations", "s", "batch_task", "queue_id"},
	} {
		access, args := targetHistoryAccessSQL(entry.alias, entry.resource, entry.column, userID, scope)
		// SQLite 和 PostgreSQL 均支持删除时给目标表设置别名。
		if _, err := tx.Exec("DELETE FROM "+entry.table+" AS "+entry.alias+" WHERE target = ?"+access, append([]interface{}{target}, args...)...); err != nil {
			return fmt.Errorf("删除目标历史失败: %w", err)
		}
	}
	if _, err := tx.Exec("DELETE FROM target_runs WHERE target = ?", target); err != nil {
		return err
	}
	if err := recomputeTargetRunAggregatesTx(tx, target); err != nil {
		return err
	}
	return tx.Commit()
}

// RecomputeTargetRunAggregates 在数据库中重算；不把全部运行明细加载到内存。
func (db *DB) RecomputeTargetRunAggregates() error {
	if db == nil {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM target_runs"); err != nil {
		return err
	}
	if err := recomputeTargetRunAggregatesTx(tx, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func recomputeTargetRunAggregatesTx(tx *Tx, target string) error {
	filter, args := "", []interface{}{time.Now().UTC()}
	if target != "" {
		filter = " WHERE target = ?"
		args = append(args, target)
	}
	_, err := tx.Exec(`INSERT INTO target_runs
		(target, run_count, first_run_at, last_run_at, last_conversation_id, last_conversation_title, last_project_id, updated_at)
		SELECT target, run_count, first_run_at, started_at, conversation_id, conversation_title, project_id, ?
		FROM (SELECT *, COUNT(*) OVER (PARTITION BY target) AS run_count,
			MIN(started_at) OVER (PARTITION BY target) AS first_run_at,
			ROW_NUMBER() OVER (PARTITION BY target ORDER BY started_at DESC, conversation_id DESC) AS rn
			FROM target_run_events`+filter+`) ranked WHERE rn = 1`, args...)
	return err
}

// BackfillTargetRunsFromConversations 优先完整任务输入/最早用户输入，缺少输入时才兼容标题。
// 只对已存在对话创建运行明细；未执行的批量任务由独立提交回填处理。
// 使用主键游标分批，不全库加载；唯一约束使重复补漏幂等。
func (db *DB) BackfillTargetRunsFromConversations() (TargetBackfillResult, error) {
	var result TargetBackfillResult
	if db == nil {
		return result, nil
	}
	// 给旧运行明细补归属快照，不从助手或日志猜测目标。
	if _, err := db.Exec(`UPDATE target_run_events SET owner_user_id = COALESCE(
		(SELECT c.owner_user_id FROM conversations c WHERE c.id = target_run_events.conversation_id), '')
		WHERE owner_user_id = '' AND EXISTS (SELECT 1 FROM conversations c WHERE c.id = target_run_events.conversation_id AND c.owner_user_id <> '')`); err != nil {
		return result, err
	}
	cursor := ""
	for {
		rows, err := db.Query(`SELECT c.id, c.title, c.project_id, c.created_at, `+conversationOriginalTargetInputSQL+`
			FROM conversations c WHERE c.id > ? ORDER BY c.id LIMIT ?`, cursor, targetHistoryBatchSize)
		if err != nil {
			return result, fmt.Errorf("读取历史对话失败: %w", err)
		}
		type input struct {
			id, title, project string
			at                 time.Time
			targets            []string
		}
		batch := make([]input, 0, targetHistoryBatchSize)
		for rows.Next() {
			var item input
			var project, original sql.NullString
			if err := rows.Scan(&item.id, &item.title, &project, &item.at, &original); err != nil {
				rows.Close()
				return result, err
			}
			item.project = project.String
			message := item.title
			if original.Valid {
				message = original.String
			}
			item.targets = targets.Extract(message)
			result.Conversations++
			if len(item.targets) > 0 {
				result.WithTargets++
			}
			batch = append(batch, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return result, err
		}
		if len(batch) == 0 {
			break
		}
		tx, err := db.Begin()
		if err != nil {
			return result, err
		}
		n := 0
		for _, item := range batch {
			for _, target := range item.targets {
				res, err := tx.Exec(insertTargetRunEventSQL, uuid.New().String(), target, item.id, item.title, item.project, item.at.UTC(), item.id)
				if err != nil {
					tx.Rollback()
					return result, fmt.Errorf("回填目标明细失败: %w", err)
				}
				affected, err := res.RowsAffected()
				if err != nil {
					tx.Rollback()
					return result, err
				}
				if affected > 0 {
					if _, err := tx.Exec(upsertTargetRunSQL, target, item.at.UTC(), item.at.UTC(), item.id, item.title, item.project, time.Now().UTC()); err != nil {
						tx.Rollback()
						return result, err
					}
					n++
				}
			}
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		result.EventsInserted += n
		cursor = batch[len(batch)-1].id
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM target_runs").Scan(&result.Targets); err != nil {
		return result, fmt.Errorf("统计目标历史失败: %w", err)
	}
	return result, nil
}

func scanTargetRun(rows interface {
	Scan(dest ...interface{}) error
}) (TargetRun, error) {
	var item TargetRun
	var first, last, submitted sql.NullString
	var conv, title, project, queue, task, taskTitle, taskProject sql.NullString
	if err := rows.Scan(&item.Target, &item.RunCount, &first, &last, &conv, &title, &project,
		&item.SubmittedCount, &submitted, &queue, &task, &taskTitle, &taskProject); err != nil {
		return item, fmt.Errorf("扫描目标历史失败: %w", err)
	}
	item.FirstRunAt, item.LastRunAt, item.LastSubmittedAt = targetHistoryTime(first), targetHistoryTime(last), targetHistoryTime(submitted)
	item.LastConversationID, item.LastConversationTitle, item.LastProjectID = conv.String, title.String, project.String
	item.LastQueueID, item.LastTaskID, item.LastTaskTitle, item.LastSubmittedProjectID = queue.String, task.String, taskTitle.String, taskProject.String
	return item, nil
}

func targetHistoryTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	at := parseDBTime(value.String)
	if at.IsZero() {
		return nil
	}
	return &at
}

func stringFromNull(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// ConversationTargetMeta 读取运行登记所需的标题、项目，不加载消息正文。
func (db *DB) ConversationTargetMeta(conversationID string) (title, projectID string, err error) {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return "", "", nil
	}
	var project *string
	if err := db.QueryRow("SELECT title, project_id FROM conversations WHERE id = ?", strings.TrimSpace(conversationID)).Scan(&title, &project); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("读取对话元信息失败: %w", err)
	}
	return title, stringFromNull(project), nil
}
