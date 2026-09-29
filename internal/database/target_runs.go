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

// TargetRun 是按「归一化域名」聚合的跑过记录，用于发起任务/对话时提示重复目标。
// RunCount 按对话去重：同一对话里的多轮追问只算一次渗透。
type TargetRun struct {
	Target                string     `json:"target"`
	RunCount              int        `json:"runCount"`
	FirstRunAt            *time.Time `json:"firstRunAt,omitempty"`
	LastRunAt             *time.Time `json:"lastRunAt,omitempty"`
	LastConversationID    string     `json:"lastConversationId,omitempty"`
	LastConversationTitle string     `json:"lastConversationTitle,omitempty"`
	LastProjectID         string     `json:"lastProjectId,omitempty"`
}

// TargetRunEvent 是一次「某对话跑了某目标」的明细。
type TargetRunEvent struct {
	ID                string    `json:"id"`
	Target            string    `json:"target"`
	ConversationID    string    `json:"conversationId"`
	ConversationTitle string    `json:"conversationTitle,omitempty"`
	ProjectID         string    `json:"projectId,omitempty"`
	StartedAt         time.Time `json:"startedAt"`
}

// TargetBackfillResult 汇总一次历史回填的结果，供启动日志说明「迁移了什么」。
type TargetBackfillResult struct {
	Conversations  int `json:"conversations"`
	WithTargets    int `json:"withTargets"`
	EventsInserted int `json:"eventsInserted"`
	Targets        int `json:"targets"`
}

const insertTargetRunEventSQL = `
	INSERT OR IGNORE INTO target_run_events
		(id, target, conversation_id, conversation_title, project_id, started_at)
	VALUES (?, ?, ?, ?, ?, ?)`

// 新目标第一次出现时插入聚合行；同目标再次（在别的对话里）出现时只要事件是新插入的，
// 就把计数 +1 并把「最近一次」指针移到本轮。first_run_at 只在首次写入。
const upsertTargetRunSQL = `
	INSERT INTO target_runs
		(target, run_count, first_run_at, last_run_at, last_conversation_id, last_conversation_title, last_project_id, updated_at)
	VALUES (?, 1, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(target) DO UPDATE SET
		run_count = target_runs.run_count + 1,
		first_run_at = COALESCE(target_runs.first_run_at, excluded.first_run_at),
		last_run_at = excluded.last_run_at,
		last_conversation_id = excluded.last_conversation_id,
		last_conversation_title = excluded.last_conversation_title,
		last_project_id = excluded.last_project_id,
		updated_at = excluded.updated_at`

// RecordTargetRuns 登记「某个对话跑了哪些目标」。
// 同一 (目标, 对话) 只登记一次，因此重复调用（多轮追问、重启后重放）不会把次数刷高。
// 返回本次新登记的目标数量（用于日志与提示）。
func (db *DB) RecordTargetRuns(conversationID, conversationTitle, projectID string, list []string, at time.Time) (int, error) {
	if db == nil {
		return 0, nil
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return 0, nil
	}
	normalized := targets.NormalizeAll(list)
	if len(normalized) == 0 {
		return 0, nil
	}
	if at.IsZero() {
		at = time.Now()
	}
	conversationTitle = strings.TrimSpace(conversationTitle)
	projectID = strings.TrimSpace(projectID)

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("登记目标运行失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	recorded := 0
	for _, target := range normalized {
		res, execErr := tx.Exec(
			insertTargetRunEventSQL,
			uuid.New().String(), target, conversationID, conversationTitle, projectID, at,
		)
		if execErr != nil {
			return recorded, fmt.Errorf("登记目标运行明细失败: %w", execErr)
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			// 这个对话早就登记过该目标，不重复计数。
			continue
		}
		if _, err := tx.Exec(
			upsertTargetRunSQL,
			target, at, at, conversationID, conversationTitle, projectID, at,
		); err != nil {
			return recorded, fmt.Errorf("更新目标聚合失败: %w", err)
		}
		recorded++
	}
	if err := tx.Commit(); err != nil {
		return recorded, fmt.Errorf("登记目标运行失败: %w", err)
	}
	return recorded, nil
}

// CheckTargetRuns 查询这批目标里哪些跑过（只返回命中的）。
func (db *DB) CheckTargetRuns(list []string) ([]TargetRun, error) {
	if db == nil {
		return nil, nil
	}
	normalized := targets.NormalizeAll(list)
	if len(normalized) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(normalized)), ",")
	args := make([]interface{}, 0, len(normalized))
	for _, t := range normalized {
		args = append(args, t)
	}
	rows, err := db.Query(`
		SELECT target, run_count, first_run_at, last_run_at, last_conversation_id, last_conversation_title, last_project_id
		FROM target_runs
		WHERE target IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("查询目标历史失败: %w", err)
	}
	defer rows.Close()

	out := make([]TargetRun, 0, len(normalized))
	for rows.Next() {
		item, scanErr := scanTargetRun(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListTargetRuns 分页列出目标历史，支持按域名关键字搜索。
func (db *DB) ListTargetRuns(keyword string, limit, offset int) ([]TargetRun, int, error) {
	if db == nil {
		return nil, 0, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	keyword = strings.ToLower(strings.TrimSpace(keyword))

	where := ""
	args := make([]interface{}, 0, 4)
	if keyword != "" {
		where = " WHERE target LIKE ?"
		args = append(args, "%"+keyword+"%")
	}

	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM target_runs"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计目标历史失败: %w", err)
	}

	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.Query(`
		SELECT target, run_count, first_run_at, last_run_at, last_conversation_id, last_conversation_title, last_project_id
		FROM target_runs`+where+`
		ORDER BY last_run_at DESC, target ASC
		LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询目标历史失败: %w", err)
	}
	defer rows.Close()

	out := make([]TargetRun, 0, limit)
	for rows.Next() {
		item, scanErr := scanTargetRun(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		out = append(out, item)
	}
	return out, total, rows.Err()
}

// ListTargetRunEvents 列出某个目标跑过的对话明细，供历史页展开与跳转。
func (db *DB) ListTargetRunEvents(target string, limit, offset int) ([]TargetRunEvent, int, error) {
	if db == nil {
		return nil, 0, nil
	}
	target = targets.Normalize(target)
	if target == "" {
		return nil, 0, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM target_run_events WHERE target = ?", target).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计目标运行明细失败: %w", err)
	}

	rows, err := db.Query(`
		SELECT id, target, conversation_id, conversation_title, project_id, started_at
		FROM target_run_events
		WHERE target = ?
		ORDER BY started_at DESC
		LIMIT ? OFFSET ?`, target, limit, offset)
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
		item.ConversationTitle = stringFromNull(title)
		item.ProjectID = stringFromNull(projectID)
		out = append(out, item)
	}
	return out, total, rows.Err()
}

// DeleteTargetRun 删除某个目标的登记（含明细），用于清理误登记的噪声目标（例如 example.com）。
func (db *DB) DeleteTargetRun(target string) error {
	if db == nil {
		return nil
	}
	target = targets.Normalize(target)
	if target == "" {
		return fmt.Errorf("目标不能为空")
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("删除目标历史失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM target_run_events WHERE target = ?", target); err != nil {
		return fmt.Errorf("删除目标运行明细失败: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM target_runs WHERE target = ?", target); err != nil {
		return fmt.Errorf("删除目标聚合失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("删除目标历史失败: %w", err)
	}
	return nil
}

// RecomputeTargetRunAggregates 依据明细表重算聚合表。
// 回填后调用一次即可，聚合值因此始终可以从明细重建，便于排错与修正。
func (db *DB) RecomputeTargetRunAggregates() error {
	if db == nil {
		return nil
	}
	rows, err := db.Query(`
		SELECT target, conversation_id, conversation_title, project_id, started_at
		FROM target_run_events
		ORDER BY started_at ASC`)
	if err != nil {
		return fmt.Errorf("读取目标运行明细失败: %w", err)
	}

	type agg struct {
		count       int
		first       time.Time
		last        time.Time
		lastConvID  string
		lastTitle   string
		lastProject string
	}
	byTarget := make(map[string]*agg)
	for rows.Next() {
		var target, conversationID string
		var title, projectID *string
		var startedAt time.Time
		if err := rows.Scan(&target, &conversationID, &title, &projectID, &startedAt); err != nil {
			_ = rows.Close()
			return fmt.Errorf("扫描目标运行明细失败: %w", err)
		}
		item, ok := byTarget[target]
		if !ok {
			item = &agg{first: startedAt}
			byTarget[target] = item
		}
		item.count++
		item.last = startedAt
		item.lastConvID = conversationID
		item.lastTitle = stringFromNull(title)
		item.lastProject = stringFromNull(projectID)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("读取目标运行明细失败: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("读取目标运行明细失败: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("重算目标聚合失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM target_runs"); err != nil {
		return fmt.Errorf("清空目标聚合失败: %w", err)
	}
	now := time.Now()
	for target, item := range byTarget {
		if _, err := tx.Exec(`
			INSERT INTO target_runs
				(target, run_count, first_run_at, last_run_at, last_conversation_id, last_conversation_title, last_project_id, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			target, item.count, item.first, item.last, item.lastConvID, item.lastTitle, item.lastProject, now,
		); err != nil {
			return fmt.Errorf("写入目标聚合失败: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("重算目标聚合失败: %w", err)
	}
	return nil
}

// BackfillTargetRunsFromConversations 从历史对话标题回填目标登记。
// 「实际跑过」的口径就是对话：批量任务真正执行时也会建对话，所以这里只扫对话即可覆盖两条路径。
// 幂等：明细表上有 (target, conversation_id) 唯一约束，重复执行不会重复计数。
func (db *DB) BackfillTargetRunsFromConversations() (TargetBackfillResult, error) {
	var result TargetBackfillResult
	if db == nil {
		return result, nil
	}
	rows, err := db.Query(`
		SELECT id, title, project_id, created_at
		FROM conversations
		ORDER BY created_at ASC`)
	if err != nil {
		return result, fmt.Errorf("读取历史对话失败: %w", err)
	}

	type convTargets struct {
		id      string
		title   string
		project string
		started time.Time
		targets []string
	}
	items := make([]convTargets, 0, 128)
	for rows.Next() {
		var id, title string
		var projectID *string
		var createdAt time.Time
		if err := rows.Scan(&id, &title, &projectID, &createdAt); err != nil {
			_ = rows.Close()
			return result, fmt.Errorf("扫描历史对话失败: %w", err)
		}
		result.Conversations++
		extracted := targets.Extract(title)
		if len(extracted) == 0 {
			continue
		}
		result.WithTargets++
		items = append(items, convTargets{
			id:      id,
			title:   title,
			project: stringFromNull(projectID),
			started: createdAt,
			targets: extracted,
		})
	}
	if err := rows.Close(); err != nil {
		return result, fmt.Errorf("读取历史对话失败: %w", err)
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("读取历史对话失败: %w", err)
	}
	if len(items) == 0 {
		return result, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return result, fmt.Errorf("回填目标历史失败: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, item := range items {
		for _, target := range item.targets {
			res, execErr := tx.Exec(
				insertTargetRunEventSQL,
				uuid.New().String(), target, item.id, item.title, item.project, item.started,
			)
			if execErr != nil {
				return result, fmt.Errorf("回填目标明细失败: %w", execErr)
			}
			if affected, _ := res.RowsAffected(); affected > 0 {
				result.EventsInserted++
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("回填目标历史失败: %w", err)
	}
	committed = true

	// 明细落库后再统一重算聚合，避免「回填 + 日常登记」两条路径各写一套聚合逻辑。
	if err := db.RecomputeTargetRunAggregates(); err != nil {
		return result, err
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
	var firstRunAt, lastRunAt *time.Time
	var lastConvID, lastTitle, lastProject *string
	if err := rows.Scan(
		&item.Target, &item.RunCount, &firstRunAt, &lastRunAt, &lastConvID, &lastTitle, &lastProject,
	); err != nil {
		return item, fmt.Errorf("扫描目标历史失败: %w", err)
	}
	item.FirstRunAt = firstRunAt
	item.LastRunAt = lastRunAt
	item.LastConversationID = stringFromNull(lastConvID)
	item.LastConversationTitle = stringFromNull(lastTitle)
	item.LastProjectID = stringFromNull(lastProject)
	return item, nil
}

func stringFromNull(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// ConversationTargetMeta 读取登记目标所需的对话元信息（标题、项目），不加载消息正文。
// 对话已被删除时返回空值而不是错误：登记只是附加信息，不该影响本轮运行。
func (db *DB) ConversationTargetMeta(conversationID string) (title, projectID string, err error) {
	if db == nil {
		return "", "", nil
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return "", "", nil
	}
	var project *string
	if err := db.QueryRow("SELECT title, project_id FROM conversations WHERE id = ?", conversationID).Scan(&title, &project); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("读取对话元信息失败: %w", err)
	}
	return title, stringFromNull(project), nil
}
