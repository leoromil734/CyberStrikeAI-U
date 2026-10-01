package database

import (
	"fmt"
	"strings"
)

// targetHistoryAccessSQL 在聚合之前过滤明细，计数、时间与最近指针均不泄露其他用户记录。
// 空用户在 ForAccess 接口中严格返回空集；全局旧接口显式使用 all。
func targetHistoryAccessSQL(alias, resourceType, resourceColumn, userID, scope string) (string, []interface{}) {
	if scope == RBACScopeAll {
		return "", nil
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return " AND 1=0", nil
	}
	query := ` AND (` + alias + `.owner_user_id = ?
		OR EXISTS (SELECT 1 FROM rbac_resource_assignments ra
			WHERE ra.user_id = ? AND ra.resource_type = '` + resourceType + `' AND ra.resource_id = ` + alias + `.` + resourceColumn + `)
		OR EXISTS (SELECT 1 FROM projects p WHERE p.id = ` + alias + `.project_id AND (p.owner_user_id = ?
			OR EXISTS (SELECT 1 FROM rbac_resource_assignments pra
				WHERE pra.user_id = ? AND pra.resource_type = 'project' AND pra.resource_id = p.id)))`
	args := []interface{}{userID, userID, userID, userID}
	// 为尚未补漏归属快照的旧数据保留安全的所属资源归属匹配。
	table := "conversations"
	if resourceType == "batch_task" {
		table = "batch_task_queues"
	}
	query += ` OR EXISTS (SELECT 1 FROM ` + table + ` parent WHERE parent.id = ` + alias + `.` + resourceColumn + ` AND parent.owner_user_id = ?))`
	return query, append(args, userID)
}

// targetHistorySourcesSQL 为查重把域名过滤推入两个明细表，为分页把搜索与权限过滤推入表。
// SQL 聚合/窗口计算只在数据库内进行，Go 不加载全库，也不逐域名发起查询。
func targetHistorySourcesSQL(filter string, filterArgs []interface{}, userID, scope string) (string, []interface{}) {
	runAccess, runArgs := targetHistoryAccessSQL("e", "conversation", "conversation_id", userID, scope)
	taskAccess, taskArgs := targetHistoryAccessSQL("s", "batch_task", "queue_id", userID, scope)
	query := `WITH run_rows AS (SELECT e.* FROM target_run_events e WHERE 1=1` + filter + runAccess + `),
		submission_rows AS (SELECT s.* FROM task_target_registrations s WHERE 1=1` + filter + taskAccess + `)`
	args := append([]interface{}{}, filterArgs...)
	args = append(args, runArgs...)
	args = append(args, filterArgs...)
	args = append(args, taskArgs...)
	return query, args
}

// Equal timestamps can occur within one scheduler tick. Prefer the existing
// aggregate's last pointer only when that conversation is already in the
// permission-filtered rows; never return metadata from an inaccessible event.
const targetHistoryMergedSQL = `,
	run_stats AS (SELECT target, COUNT(*) AS run_count, MIN(started_at) AS first_run_at, MAX(started_at) AS last_run_at FROM run_rows GROUP BY target),
	run_latest AS (SELECT rr.*, ROW_NUMBER() OVER (PARTITION BY rr.target ORDER BY rr.started_at DESC,
		CASE WHEN rr.conversation_id = (SELECT tr.last_conversation_id FROM target_runs tr WHERE tr.target = rr.target) THEN 1 ELSE 0 END DESC,
		rr.conversation_id DESC) AS rn FROM run_rows rr),
	submission_stats AS (SELECT target, COUNT(*) AS submitted_count, MAX(created_at) AS last_submitted_at FROM submission_rows GROUP BY target),
	submission_latest AS (SELECT *, ROW_NUMBER() OVER (PARTITION BY target ORDER BY created_at DESC, queue_id DESC, task_id DESC) AS rn FROM submission_rows),
	all_targets AS (SELECT target FROM run_rows UNION SELECT target FROM submission_rows)
	SELECT a.target, COALESCE(r.run_count, 0), r.first_run_at, r.last_run_at,
		l.conversation_id, l.conversation_title, l.project_id,
		COALESCE(s.submitted_count, 0), s.last_submitted_at, t.queue_id, t.task_id, t.task_title, t.project_id
	FROM all_targets a
	LEFT JOIN run_stats r ON r.target = a.target
	LEFT JOIN run_latest l ON l.target = a.target AND l.rn = 1
	LEFT JOIN submission_stats s ON s.target = a.target
	LEFT JOIN submission_latest t ON t.target = a.target AND t.rn = 1`

func (db *DB) queryTargetHistory(query string, args []interface{}, capacity int) ([]TargetRun, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询目标历史失败: %w", err)
	}
	defer rows.Close()
	out := make([]TargetRun, 0, capacity)
	for rows.Next() {
		item, err := scanTargetRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
