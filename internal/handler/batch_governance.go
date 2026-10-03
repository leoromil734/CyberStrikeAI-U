package handler

import (
	"encoding/json"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/database"
	"github.com/google/uuid"
)

func deduplicateBatchTaskInputs(inputs []BatchTaskInput) ([]BatchTaskInput, int) {
	type key struct{ message, channel string }
	seen := make(map[key]struct{}, len(inputs))
	out := make([]BatchTaskInput, 0, len(inputs))
	skipped := 0
	for _, input := range inputs {
		k := key{strings.TrimSpace(input.Message), strings.TrimSpace(input.AIChannelID)}
		if _, exists := seen[k]; exists {
			skipped++
			continue
		}
		seen[k] = struct{}{}
		out = append(out, input)
	}
	return out, skipped
}

// The manifest is a work inventory, never an inferred authorization. Original
// task URL/path/port restrictions stay in batch_tasks.message. The model may
// describe the actual scope_kind but cannot obtain permission by changing it.
func (h *AgentHandler) beginGovernedBatchRun(queue *BatchTaskQueue, task *BatchTask, conversationID, projectID, assistantMessageID string, resuming bool) (*database.AssessmentRun, string, error) {
	mode := queue.AssessmentMode
	if mode == "" {
		mode = database.AssessmentModeLegacy
	}
	assessmentID := ""
	if mode == database.AssessmentModeComprehensive {
		if projectID == "" {
			return nil, "", fmt.Errorf("全面评估缺少项目绑定")
		}
		if resuming {
			if previous, err := h.db.LatestAssessmentRun(conversationID); err != nil {
				return nil, "", err
			} else if previous != nil && previous.QueueID == queue.ID && previous.TaskID == task.ID && previous.Mode == mode && previous.ProjectID == projectID {
				assessmentID = previous.AssessmentID
			}
			facts, err := h.db.ListProjectCoverageFacts(projectID, conversationID)
			if err != nil {
				return nil, "", err
			}
			var newest *database.ProjectFact
			for _, f := range facts {
				if f.SourceConversationID == conversationID && strings.HasPrefix(f.FactKey, "recon/assessment/") && (newest == nil || f.UpdatedAt.After(newest.UpdatedAt)) {
					newest = f
				}
			}
			if assessmentID == "" && newest != nil {
				assessmentID = strings.TrimPrefix(newest.FactKey, "recon/assessment/")
			}
		}
		if assessmentID == "" {
			assessmentID = "run-" + strings.ReplaceAll(uuid.NewString(), "-", "")
			body, _ := json.Marshal(map[string]interface{}{
				"schema_version": 2, "mode": "comprehensive", "assessment_id": assessmentID, "status": "active",
				"scope_kind": "asset-list", "endpoint_count": 0, "js_count": 0, "risk_unit_count": 0,
				"scope_ref": "batch_task:" + queue.ID + "/" + task.ID,
				"notes":     "服务端初始化；原始任务中的URL/路径/端口及授权边界保持不变，需按真实库存更新。",
			})
			_, err := h.db.UpsertProjectFactPatch(&database.ProjectFact{ProjectID: projectID, FactKey: "recon/assessment/" + assessmentID,
				Category: "recon", Summary: "全面评估已初始化；尚未采集和验证，不代表覆盖完成。", Body: string(body), Confidence: "tentative",
				SourceConversationID: conversationID, SourceMessageID: assistantMessageID}, database.ProjectFactPatchFields{})
			if err != nil {
				return nil, "", err
			}
		}
	}
	run, err := h.db.BeginAssessmentRun(conversationID, projectID, queue.ID, task.ID, mode, assessmentID)
	if err != nil {
		return nil, "", err
	}
	instruction := ""
	if assessmentID != "" {
		instruction = fmt.Sprintf("\n\n## 本轮服务端交付策略\nassessment_id=%s；已创建 recon/assessment/%s，沿用该清单，不另建更小的清单。原始任务决定目标/URL/路径/端口和方法授权，清单不扩大范围。按实际范围更新 scope_kind、真实端点/JS/风险库存和阶段，原件引用关联 execution_id；未测或部分结果保留 gap/blocked。工具大输出继续落盘，只提取新增认知。身份由用户提供或按任务明确条件使用，不为满足门禁绕过验证码/MFA。\n", assessmentID, assessmentID)
	}
	return run, instruction, nil
}

func (h *AgentHandler) decorateBatchQueueActivity(queue *BatchTaskQueue) {
	if queue == nil {
		return
	}
	for _, task := range queue.Tasks {
		if task == nil {
			continue
		}
		task.Outcome = agentfinalizer.Outcome(task.Status, "", task.Result)
		if h.db != nil && task.ConversationID != "" {
			if run, err := h.db.LatestAssessmentRun(task.ConversationID); err == nil && run != nil {
				task.LatestRun = run
				if run.QueueID == queue.ID && run.TaskID == task.ID && run.Status != "running" && task.CompletedAt != nil && !run.StartedAt.After(*task.CompletedAt) {
					task.Outcome = run.Outcome
				}
			}
		}
		if h.tasks != nil && task.ConversationID != "" {
			if active := h.tasks.GetTaskSnapshot(task.ConversationID); active != nil {
				task.ConversationActive = active.Status == "running" || active.Status == "cancelling"
			}
		}
	}
}
