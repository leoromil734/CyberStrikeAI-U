// Package agentfinalizer 实现 Agent 最终回复治理（Finalization Contract）。
//
// 设计动机：模型输出的自然语言只是「候选」，不能直接作为交付结论。
// 只要代理仍在调用工具、有后台执行未结束、缺少执行证据、等待人工审批或输出为空，
// 就不允许把候选文本提升为最终回复。本包是唯一的判定契约。
//
// 核心规则：
//  1. Finalizable=false 时禁止发送 response 终态事件，也不得写入 messages.content。
//  2. 存在 queued/running 的工具执行时判定 in_progress。
//  3. 显式要求执行证据（RequireExecutionEvidence）时，必须有 completed 的工具执行记录。
//  4. 空输出、等待 HITL、非成功 status 一律阻断。
package agentfinalizer

import (
	"strings"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"
)

const (
	StatusCompleted    = "completed"
	StatusInProgress   = "in_progress"
	StatusBlocked      = "blocked"
	StatusFailed       = "failed"
	StatusCancelled    = "cancelled"
	StatusAwaitingHITL = "awaiting_hitl"

	ReasonVerified        = "verified"
	ReasonPendingTools    = "pending_tool_executions"
	ReasonEmptyResponse   = "empty_response"
	ReasonAwaitingHITL    = "awaiting_hitl"
	ReasonFailed          = "failed"
	ReasonCancelled       = "cancelled"
	ReasonMissingEvidence = "missing_execution_evidence"
)

// Decision is the single contract that may promote an agent run to a final
// user-facing answer. Natural-language assistant text is only a candidate until
// this object says Finalizable.
type Decision struct {
	Status               string   `json:"status"`
	Finalizable          bool     `json:"finalizable"`
	Finalized            bool     `json:"finalized"`
	CompletionReason     string   `json:"completionReason"`
	FinalText            string   `json:"finalText,omitempty"`
	EvidenceVerified     bool     `json:"evidenceVerified"`
	EvidenceRefs         []string `json:"evidenceRefs,omitempty"`
	PendingExecutionIDs  []string `json:"pendingExecutionIds,omitempty"`
	PendingToolRuns      []string `json:"pendingToolRuns,omitempty"`
	MissingChecks        []string `json:"missingChecks,omitempty"`
	AgentMode            string   `json:"agentMode,omitempty"`
	ConversationID       string   `json:"conversationId,omitempty"`
	AssistantMessageID   string   `json:"messageId,omitempty"`
	CandidateResponseLen int      `json:"candidateResponseLen,omitempty"`
}

// Input 判定输入。Response 为候选文本，其余为运行时状态与策略。
type Input struct {
	Response                 string
	MCPExecutionIDs          []string
	ConversationID           string
	AssistantMessageID       string
	AgentMode                string
	Status                   string
	CompletionReason         string
	AwaitingHITL             bool
	RequireExecutionEvidence bool
}

// FromRunResult 依据 RunResult 做判定，并把终态字段回填到 result，便于统一读写。
func FromRunResult(db *database.DB, result *multiagent.RunResult, in Input) Decision {
	if result != nil {
		if strings.TrimSpace(in.Response) == "" {
			in.Response = result.Response
		}
		if len(in.MCPExecutionIDs) == 0 {
			in.MCPExecutionIDs = result.MCPExecutionIDs
		}
		if strings.TrimSpace(in.Status) == "" {
			in.Status = result.Status
		}
		if strings.TrimSpace(in.CompletionReason) == "" {
			in.CompletionReason = result.CompletionReason
		}
	}
	d := Decide(db, in)
	if result != nil {
		result.Finalized = d.Finalized
		result.Status = d.Status
		result.CompletionReason = d.CompletionReason
		result.EvidenceVerified = d.EvidenceVerified
		result.EvidenceRefs = append([]string(nil), d.EvidenceRefs...)
		result.PendingExecutionIDs = append([]string(nil), d.PendingExecutionIDs...)
		result.MissingChecks = append([]string(nil), d.MissingChecks...)
	}
	return d
}

// Decide 是纯函数式判定：输入候选文本与执行证据，输出是否可交付。
func Decide(db *database.DB, in Input) Decision {
	text := strings.TrimSpace(in.Response)
	status := strings.TrimSpace(in.Status)
	if status == "" {
		status = StatusCompleted
	}
	reason := strings.TrimSpace(in.CompletionReason)
	if reason == "" {
		reason = ReasonVerified
	}
	d := Decision{
		Status:               status,
		CompletionReason:     reason,
		FinalText:            text,
		EvidenceVerified:     true,
		EvidenceRefs:         evidenceRefs(in.MCPExecutionIDs),
		AgentMode:            strings.TrimSpace(in.AgentMode),
		ConversationID:       strings.TrimSpace(in.ConversationID),
		AssistantMessageID:   strings.TrimSpace(in.AssistantMessageID),
		CandidateResponseLen: len([]rune(text)),
	}

	if in.AwaitingHITL {
		d.Status = StatusAwaitingHITL
		d.CompletionReason = ReasonAwaitingHITL
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, "workflow is awaiting HITL approval")
		return d
	}
	if isEmptyCandidate(text) {
		d.Status = StatusBlocked
		d.CompletionReason = ReasonEmptyResponse
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, "assistant final text is empty or only an empty-response placeholder")
		return d
	}
	switch status {
	case StatusInProgress, StatusBlocked, StatusFailed, StatusCancelled, StatusAwaitingHITL:
		d.Status = status
		d.EvidenceVerified = false
		if d.CompletionReason == ReasonVerified {
			d.CompletionReason = status
		}
		d.MissingChecks = append(d.MissingChecks, "agent run status is "+status)
		return d
	}

	pending := pendingExecutions(db, in.MCPExecutionIDs)
	if len(pending) > 0 {
		d.Status = StatusInProgress
		d.CompletionReason = ReasonPendingTools
		d.EvidenceVerified = false
		d.PendingExecutionIDs = pending
		d.PendingToolRuns = append([]string(nil), pending...)
		d.MissingChecks = append(d.MissingChecks, "tool execution still queued or running")
		return d
	}

	if in.RequireExecutionEvidence && !hasCompletedEvidence(db, in.MCPExecutionIDs) {
		d.Status = StatusBlocked
		d.CompletionReason = ReasonMissingEvidence
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, "execution evidence is required but no completed tool execution was recorded")
		return d
	}

	d.Finalizable = true
	d.Finalized = true
	d.Status = StatusCompleted
	if d.CompletionReason == "" {
		d.CompletionReason = ReasonVerified
	}
	return d
}

// ResponsePayload 生成 SSE response 事件需要携带的终态字段。
func ResponsePayload(d Decision, extra map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{
		"finalized":           d.Finalized,
		"finalizable":         d.Finalizable,
		"status":              d.Status,
		"completionReason":    d.CompletionReason,
		"evidenceVerified":    d.EvidenceVerified,
		"evidenceRefs":        d.EvidenceRefs,
		"pendingExecutionIds": d.PendingExecutionIDs,
		"pendingToolRuns":     d.PendingToolRuns,
		"missingChecks":       d.MissingChecks,
	}
	if d.ConversationID != "" {
		out["conversationId"] = d.ConversationID
	}
	if d.AssistantMessageID != "" {
		out["messageId"] = d.AssistantMessageID
	}
	if d.AgentMode != "" {
		out["agentMode"] = d.AgentMode
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func isEmptyCandidate(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	return strings.Contains(s, "no assistant text was captured") ||
		strings.Contains(s, "未捕获到助手文本输出")
}

func evidenceRefs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, "mcp_execution:"+id)
	}
	return out
}

func pendingExecutions(db *database.DB, ids []string) []string {
	if db == nil || len(ids) == 0 {
		return nil
	}
	out := make([]string, 0)
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		exec, err := db.GetToolExecution(id)
		if err != nil || exec == nil {
			continue
		}
		switch strings.TrimSpace(exec.Status) {
		case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning:
			out = append(out, id)
		}
	}
	return out
}

func hasCompletedEvidence(db *database.DB, ids []string) bool {
	if db == nil || len(ids) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		exec, err := db.GetToolExecution(id)
		if err != nil || exec == nil {
			continue
		}
		if strings.TrimSpace(exec.Status) == mcp.ToolExecutionStatusCompleted {
			return true
		}
	}
	return false
}
