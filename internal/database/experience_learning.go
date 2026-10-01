package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	em "cyberstrike-ai/internal/experience/model"
	"cyberstrike-ai/internal/mcp"
)

func (db *DB) SetExperienceLearningEnabled(enabled bool) { db.experienceLearningEnabled.Store(enabled) }

// RegisterExperienceToolDefinition is called whenever a tool definition changes.
// Hashing the complete definition invalidates memories on schema/config changes.
func (db *DB) RegisterExperienceToolDefinition(tool mcp.Tool) {
	b, err := json.Marshal(tool)
	if err == nil {
		db.experienceToolFingerprints.Store(tool.Name, em.Hash(b))
	}
}
func (db *DB) ExperienceToolFingerprint(name string) string {
	v, ok := db.experienceToolFingerprints.Load(name)
	if !ok {
		return ""
	}
	return v.(string)
}

func (db *DB) shouldQueueExperience(exec *mcp.ToolExecution) bool {
	return db.experienceLearningEnabled.Load() && exec != nil && exec.OwnerUserID != "" && exec.ConversationID != "" &&
		(exec.Status == mcp.ToolExecutionStatusQueued || exec.Status == mcp.ToolExecutionStatusRunning || exec.Status == mcp.ToolExecutionStatusFailed || exec.Status == mcp.ToolExecutionStatusCompleted) &&
		!strings.HasPrefix(exec.ToolName, "search_") && !strings.Contains(exec.ToolName, "experience") && db.ExperienceToolFingerprint(exec.ToolName) != ""
}

func (db *DB) enqueueExperienceTx(tx *Tx, exec *mcp.ToolExecution) error {
	_, err := tx.Exec(`INSERT INTO experience_execution_metadata (execution_id, tool_schema_hash, platform) VALUES (?, ?, ?) ON CONFLICT(execution_id) DO NOTHING`, exec.ID, db.ExperienceToolFingerprint(exec.ToolName), runtime.GOOS+"/"+runtime.GOARCH)
	if err != nil {
		return err
	}
	if exec.EndTime == nil || (exec.Status != mcp.ToolExecutionStatusFailed && exec.Status != mcp.ToolExecutionStatusCompleted) {
		return nil
	}
	var schemaHash, platform string
	if err := tx.QueryRow(`SELECT tool_schema_hash, platform FROM experience_execution_metadata WHERE execution_id = ?`, exec.ID).Scan(&schemaHash, &platform); err != nil {
		return err
	}
	shape, err := json.Marshal(em.ArgumentShape(exec.Arguments))
	if err != nil {
		return err
	}
	// Keep only bounded, sanitized parameter structure; raw outputs stay in monitor storage.
	if len(shape) > 32*1024 {
		return nil
	}
	class := em.ErrorClass(exec.Error)
	if class == "" && exec.Result != nil {
		for _, c := range exec.Result.Content {
			if c.Type == "text" {
				class = em.ErrorClass(c.Text)
				if class != "" {
					break
				}
			}
		}
	}
	_, err = tx.Exec(`INSERT INTO experience_learning_events
	 (id, execution_id, owner_user_id, conversation_id, tool_name, tool_schema_hash, platform, status, arguments_shape, error_class, started_at, finished_at)
	 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(execution_id) DO NOTHING`,
		exec.ID, exec.ID, exec.OwnerUserID, exec.ConversationID, exec.ToolName, schemaHash, platform, exec.Status, string(shape), class, exec.StartTime, *exec.EndTime)
	return err
}

type experienceEvent struct {
	ID, ExecutionID, Owner, ConversationID, Tool, SchemaHash, Platform, Status, Arguments, ErrorClass string
	StartedAt, FinishedAt                                                                             time.Time
}

const experienceEventColumns = `id, execution_id, owner_user_id, conversation_id, tool_name, tool_schema_hash, platform, status, arguments_shape, error_class, started_at, finished_at`

func scanExperienceEvent(row experienceScanner) (experienceEvent, error) {
	var e experienceEvent
	err := row.Scan(&e.ID, &e.ExecutionID, &e.Owner, &e.ConversationID, &e.Tool, &e.SchemaHash, &e.Platform, &e.Status, &e.Arguments, &e.ErrorClass, &e.StartedAt, &e.FinishedAt)
	return e, err
}

// ProcessExperienceEvents is safe to repeat after restart and across consumers.
// Pairing is deliberately conservative: same principal, conversation, tool,
// definition and environment, sequential calls within ten minutes.
func (db *DB) ProcessExperienceEvents(ctx context.Context, limit int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM experience_learning_events WHERE state = 'pending' AND attempts < 5 ORDER BY finished_at, id LIMIT ?`, limit)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		if err := db.processExperienceEvent(ctx, id); err != nil {
			// No customer text or database diagnostics are saved in the event error.
			_, _ = db.Exec(`UPDATE experience_learning_events SET attempts = attempts + 1, state = CASE WHEN attempts + 1 >= 5 THEN 'failed' ELSE 'pending' END, last_error = 'processing failed' WHERE id = ? AND state = 'pending'`, id)
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func (db *DB) processExperienceEvent(ctx context.Context, id string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Updating in this transaction takes a row/write lock; rollback leaves it pending.
	res, err := tx.ExecContext(ctx, `UPDATE experience_learning_events SET state = 'processing' WHERE id = ? AND state = 'pending'`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	e, err := scanExperienceEvent(tx.QueryRowContext(ctx, `SELECT `+experienceEventColumns+` FROM experience_learning_events WHERE id = ?`, id))
	if err != nil {
		return err
	}
	if e.Status == mcp.ToolExecutionStatusCompleted {
		previous, prevErr := scanExperienceEvent(tx.QueryRowContext(ctx, `SELECT `+experienceEventColumns+` FROM experience_learning_events WHERE owner_user_id = ? AND conversation_id = ? AND tool_name = ? AND tool_schema_hash = ? AND platform = ? AND finished_at <= ? AND finished_at >= ? AND execution_id <> ? ORDER BY finished_at DESC, id DESC LIMIT 1`, e.Owner, e.ConversationID, e.Tool, e.SchemaHash, e.Platform, e.StartedAt, e.StartedAt.Add(-10*time.Minute), e.ExecutionID))
		if prevErr != nil && !errors.Is(prevErr, sql.ErrNoRows) {
			return prevErr
		}
		if prevErr == nil && previous.Status == mcp.ToolExecutionStatusFailed && previous.ErrorClass != "" && previous.Arguments != e.Arguments {
			p := em.Proposal{Content: em.Content{
				Kind: em.KindToolRepair, Title: "工具参数修复：" + e.Tool,
				Summary:      "观察到参数错误后调用完成；这是结构化修复候选，尚需审核语义与实际输出。",
				Conditions:   em.Conditions{ToolName: e.Tool, ToolSchemaHash: e.SchemaHash, Platform: e.Platform},
				Steps:        []string{"失败调用的脱敏参数结构：" + previous.Arguments, "修正后调用的脱敏参数结构：" + e.Arguments, "将占位符绑定本次输入；保留任务语义、授权及安全检查。"},
				Verification: "审核原始失败与修正执行记录，确认预期结果结构和任务语义；正常退出不等于验证成功。",
				FailureNotes: []string{"仅学习参数结构，原始目标、命令、凭据和输出不会进入共享正文。", "接口结构哈希不代表工具二进制版本；升级工具后需重新复核。"},
			}, Evidence: []em.Evidence{{ExecutionID: previous.ExecutionID, Role: "failed"}, {ExecutionID: e.ExecutionID, Role: "corrected"}}}
			// Retain project attribution, but never automatically publish across projects.
			var project sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT project_id FROM conversations WHERE id = ?`, e.ConversationID).Scan(&project); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			p.OriginProjectID = project.String
			if err := em.Normalize(&p.Content); err != nil {
				return fmt.Errorf("invalid learned candidate: %w", err)
			}
			if _, err := createExperienceTx(tx, e.Owner, p); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE experience_learning_events SET state = 'done', last_error = '' WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) ExperienceQueueStats() (map[string]int, error) {
	rows, err := db.Query(`SELECT state, COUNT(*) FROM experience_learning_events GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return nil, err
		}
		out[state] = n
	}
	return out, rows.Err()
}
