package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"cyberstrike-ai/internal/pilab"
)

const piPlatformPreparingMessage = "PI 正式任务准备中，尚未形成结论。"

// Recover reconciles metadata after an unclean process exit. It never starts a
// model or tool and never overwrites a newer conversation message. The exact
// owner/project/message binding is checked before using privileged DB access.
func (p *PILabPlatform) Recover(owner string, run *pilab.Run) error {
	if p == nil || p.db == nil || run == nil || run.Mode != pilab.ModePlatform {
		return nil
	}
	projectID, err := p.db.GetConversationProjectID(run.ConversationID)
	if err != nil || projectID != run.ProjectID || p.db.GetResourceOwner("conversation", run.ConversationID) != owner {
		return pilab.ErrForbidden
	}
	var conversation, role, content, executionJSON string
	messageExists := false
	if run.AssistantMessageID != "" {
		err = p.db.QueryRow("SELECT conversation_id, role, content, COALESCE(mcp_execution_ids,'') FROM messages WHERE id = ?", run.AssistantMessageID).Scan(&conversation, &role, &content, &executionJSON)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return pilab.ErrStorage
		}
		if err == nil {
			if conversation != run.ConversationID || role != "assistant" {
				return pilab.ErrForbidden
			}
			messageExists = true
		}
	}
	var status, reason string
	err = p.db.QueryRow("SELECT status, COALESCE(completion_reason,'') FROM assessment_runs WHERE conversation_id = ? AND assessment_id = ? ORDER BY started_at DESC LIMIT 1", run.ConversationID, run.ID).Scan(&status, &reason)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return pilab.ErrStorage
	}
	// The DB finalization may have committed immediately before the PI snapshot.
	// Preserve that completed delivery instead of fabricating a new execution.
	if status != "" && status != "running" && messageExists && strings.TrimSpace(content) != "" && content != piPlatformPreparingMessage {
		run.Report = content
		switch status {
		case "completed":
			run.Status = "completed"
			run.Error = ""
		case "failed":
			run.Status = "failed"
			run.Error = reason
		case "blocked", "timeout":
			run.Status = "partial"
			run.Error = reason
		}
		var ids []string
		if json.Unmarshal([]byte(executionJSON), &ids) == nil && len(ids) <= 2000 {
			run.ExecutionIDs = ids
		}
		return nil
	}
	notice := "PI 服务在运行期间中断，本次任务未自动重跑，也未确认完整覆盖。已有执行证据保留在原项目和工具监控中；可按原配置新建任务继续。"
	if strings.TrimSpace(run.Report) == "" {
		run.Report = notice
	} else {
		run.Report = notice + "\n\n以下为中断前保存的候选报告，不能视为完成证明：\n\n" + run.Report
	}
	if messageExists && (strings.TrimSpace(content) == "" || content == piPlatformPreparingMessage) {
		if _, err = p.db.Exec("UPDATE messages SET content = ?, updated_at = ? WHERE id = ? AND conversation_id = ? AND role = 'assistant' AND content = ?", run.Report, time.Now(), run.AssistantMessageID, run.ConversationID, content); err != nil {
			return pilab.ErrStorage
		}
	}
	_, err = p.db.Exec("UPDATE assessment_runs SET status = 'cancelled', completion_reason = 'pi_service_interrupted', outcome = 'cancelled', ended_at = ? WHERE conversation_id = ? AND assessment_id = ? AND status = 'running'", time.Now(), run.ConversationID, run.ID)
	if err != nil {
		return pilab.ErrStorage
	}
	return nil
}
