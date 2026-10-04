package agentfinalizer

import (
	"context"
	"database/sql"
	"time"

	"cyberstrike-ai/internal/database"
)

const (
	stoppedDeliveryReadTimeout = 2 * time.Second
	stoppedToolGroupLimit      = 16
	stoppedExecutionLimit      = 20
	stoppedFindingLimit        = 20
)

type stoppedToolGroup struct {
	Name, Status string
	Count        int
}

type stoppedExecution struct {
	ID, Name, Status string
}

type stoppedFinding struct {
	ID, Title, Severity, Status string
}

type stoppedDeliverySnapshot struct {
	Title, ProjectName, ScopeJSON string
	ConversationKnown             bool
	Issues                        []string

	ToolCountsKnown                               bool
	ToolTotal, Completed, Failed, Queued, Running int
	ToolGroups                                    []stoppedToolGroup
	ToolGroupsCapped                              bool
	Executions                                    []stoppedExecution
	ExecutionsCapped                              bool

	FindingCountKnown bool
	FindingCount      int
	Findings          []stoppedFinding
}

// readStoppedDeliverySnapshot reads metadata only. Never load conversation
// messages, tool arguments/results/errors, vulnerability evidence, or fact bodies.
// Every query is tied to the existing conversation; findings also have to match
// its current project binding. Decision evidence IDs are NOT lookup authority.
// LIMITs bound rows, SUBSTR bounds untrusted columns, and a shared deadline bounds
// aggregate work. Do not re-run the potentially large coverage gate here.
func readStoppedDeliverySnapshot(db *database.DB, conversationID string) stoppedDeliverySnapshot {
	var s stoppedDeliverySnapshot
	if db == nil || db.DB == nil {
		s.Issues = append(s.Issues, "数据库不可用，已保存记录无法核实；本报告仅使用停止时的决策快照。")
		return s
	}
	if conversationID == "" {
		s.Issues = append(s.Issues, "缺少会话标识，无法安全限定读取范围；未查询其他会话或项目。")
		return s
	}
	ctx, cancel := context.WithTimeout(context.Background(), stoppedDeliveryReadTimeout)
	defer cancel()

	var projectID string
	err := db.QueryRowContext(ctx, `SELECT SUBSTR(title,1,241), COALESCE(project_id,'')
		FROM conversations WHERE id = ?`, conversationID).Scan(&s.Title, &projectID)
	if err != nil {
		if err == sql.ErrNoRows {
			s.Issues = append(s.Issues, "会话已删除或不存在，历史记录无法核实；未读取可能残留的执行或漏洞记录。")
		} else {
			s.Issues = append(s.Issues, "会话信息读取失败，已保存记录无法核实；未扩大查询范围。")
		}
		return s
	}
	s.ConversationKnown = true
	if projectID != "" {
		err = db.QueryRowContext(ctx, `SELECT SUBSTR(p.name,1,241), SUBSTR(COALESCE(p.scope_json,''),1,?)
			FROM projects p JOIN conversations c ON c.project_id = p.id
			WHERE c.id = ? AND p.id = ?`, stoppedScopeReadLimit+1, conversationID, projectID).
			Scan(&s.ProjectName, &s.ScopeJSON)
		if err != nil {
			s.Issues = append(s.Issues, "绑定项目的名称或登记范围读取失败；任务授权范围仍需人工核对。")
		}
	}

	// The aggregate covers the whole conversation, even when the displayed
	// tool groups/IDs are capped. Unknown or custom statuses are not successes.
	err = db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN t.status = 'failed' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN t.status = 'queued' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN t.status = 'running' THEN 1 ELSE 0 END),0)
		FROM tool_executions t JOIN conversations c ON c.id = t.conversation_id
		WHERE c.id = ?`, conversationID).
		Scan(&s.ToolTotal, &s.Completed, &s.Failed, &s.Queued, &s.Running)
	s.ToolCountsKnown = err == nil
	if err != nil {
		s.Issues = append(s.Issues, "工具执行总数及未完成数量读取失败，数量未知，不能按零条理解。")
	}

	err = readStoppedRows(ctx, db, `SELECT SUBSTR(t.tool_name,1,241), SUBSTR(t.status,1,241), COUNT(*)
		FROM tool_executions t JOIN conversations c ON c.id = t.conversation_id
		WHERE c.id = ? GROUP BY t.tool_name,t.status
		ORDER BY COUNT(*) DESC,t.tool_name,t.status LIMIT ?`, []any{conversationID, stoppedToolGroupLimit + 1}, func(rows *sql.Rows) error {
		var group stoppedToolGroup
		if err := rows.Scan(&group.Name, &group.Status, &group.Count); err != nil {
			return err
		}
		if len(s.ToolGroups) < stoppedToolGroupLimit {
			s.ToolGroups = append(s.ToolGroups, group)
		} else {
			s.ToolGroupsCapped = true
		}
		return nil
	})
	if err != nil {
		s.Issues = append(s.Issues, "按工具和状态汇总的读取不完整，已读条目仅为部分记录。")
	}

	// Prioritize queued/running records so a stopped loop does not conceal
	// detached tools. This is a display order, never a tool-state transition.
	err = readStoppedRows(ctx, db, `SELECT SUBSTR(t.id,1,241), SUBSTR(t.tool_name,1,241), SUBSTR(t.status,1,241)
		FROM tool_executions t JOIN conversations c ON c.id = t.conversation_id
		WHERE c.id = ? ORDER BY CASE WHEN t.status IN ('queued','running') THEN 0 ELSE 1 END,
		t.start_time DESC,t.id DESC LIMIT ?`, []any{conversationID, stoppedExecutionLimit + 1}, func(rows *sql.Rows) error {
		var execution stoppedExecution
		if err := rows.Scan(&execution.ID, &execution.Name, &execution.Status); err != nil {
			return err
		}
		if len(s.Executions) < stoppedExecutionLimit {
			s.Executions = append(s.Executions, execution)
		} else {
			s.ExecutionsCapped = true
		}
		return nil
	})
	if err != nil {
		s.Issues = append(s.Issues, "可核对执行 ID 的读取不完整；原始执行仍需在本会话详情核查。")
	}

	const findingScope = ` FROM vulnerabilities v JOIN conversations c ON c.id = v.conversation_id
		WHERE c.id = ? AND COALESCE(v.project_id,'') = COALESCE(c.project_id,'')`
	err = db.QueryRowContext(ctx, `SELECT COUNT(*)`+findingScope, conversationID).Scan(&s.FindingCount)
	s.FindingCountKnown = err == nil
	if err != nil {
		s.Issues = append(s.Issues, "该会话的漏洞登记数量读取失败，登记数量未知；不能按零漏洞理解。")
	}
	err = readStoppedRows(ctx, db, `SELECT SUBSTR(v.id,1,241), SUBSTR(v.title,1,241),
		SUBSTR(v.severity,1,241), SUBSTR(v.status,1,241)`+findingScope+`
		ORDER BY v.created_at DESC,v.id DESC LIMIT ?`, []any{conversationID, stoppedFindingLimit}, func(rows *sql.Rows) error {
		var finding stoppedFinding
		if err := rows.Scan(&finding.ID, &finding.Title, &finding.Severity, &finding.Status); err != nil {
			return err
		}
		s.Findings = append(s.Findings, finding)
		return nil
	})
	if err != nil {
		s.Issues = append(s.Issues, "该会话的漏洞登记明细读取不完整；已读条目不代表完整列表。")
	}
	return s
}

func readStoppedRows(ctx context.Context, db *database.DB, query string, args []any, scan func(*sql.Rows) error) error {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
