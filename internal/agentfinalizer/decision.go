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
//  5. 候选文本其实是上游错误说明（HTTP 200 + 错误正文）时判定 failed，不得当结论交付。
//  6. 短候选文本若是「没说完」的半截话（下一步叙述 / 缺句末标点）判定 in_progress，转自动续跑。
package agentfinalizer

import (
	"regexp"
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

	ReasonVerified           = "verified"
	ReasonPendingTools       = "pending_tool_executions"
	ReasonEmptyResponse      = "empty_response"
	ReasonAwaitingHITL       = "awaiting_hitl"
	ReasonFailed             = "failed"
	ReasonCancelled          = "cancelled"
	ReasonMissingEvidence    = "missing_execution_evidence"
	ReasonCoverageIncomplete = "coverage_incomplete"
	// ReasonIncompleteCandidate 候选文本是「没说完」的半截话（下一步叙述或缺少句末标点）。
	// 与空回复不同：文本非空但明显不是结论，转自动续跑而不是直接交付。
	ReasonIncompleteCandidate = "incomplete_candidate_response"
	// ReasonUpstreamErrorText 候选文本其实是上游网关/供应商的错误说明（HTTP 200 + 错误正文），
	// 不能当作模型结论交付。
	ReasonUpstreamErrorText = "upstream_error_text"
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
	CoverageValidFacts   int      `json:"coverageValidFacts,omitempty"`
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
	RequireCoverageEvidence  bool
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

	// 上游网关有时以 HTTP 200 返回错误说明（正文是 "AI provider temporarily unavailable" 之类），
	// 必须判为失败，否则错误会被当成成功结论交付。
	if looksLikeUpstreamErrorText(text) {
		d.Status = StatusFailed
		d.CompletionReason = ReasonUpstreamErrorText
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, "candidate text is an upstream provider/gateway error message, not an agent answer")
		return d
	}

	// 文本非空但明显是半截话（「接下来我去看 X」或缺少句末标点）：不能交付，交给自动续跑再跑一段。
	if why := incompleteCandidateReason(text); why != "" {
		d.Status = StatusInProgress
		d.CompletionReason = ReasonIncompleteCandidate
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, why)
		return d
	}

	if in.RequireExecutionEvidence && !hasCompletedEvidence(db, in.MCPExecutionIDs) {
		d.Status = StatusBlocked
		d.CompletionReason = ReasonMissingEvidence
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, "execution evidence is required but no completed tool execution was recorded")
		return d
	}

	coverage := coverageForDelivery(db, in)
	d.CoverageValidFacts = coverage.ValidFacts
	if coverage.Active && len(coverage.Missing) > 0 {
		d.Status = StatusInProgress
		d.CompletionReason = ReasonCoverageIncomplete
		d.EvidenceVerified = false
		d.MissingChecks = append(d.MissingChecks, coverage.Missing...)
		return d
	}
	d.EvidenceRefs = append(d.EvidenceRefs, coverage.EvidenceRefs...)

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

const (
	// 只对短候选做完整性判定：长报告多为正常交付，误判成本高。
	incompleteCandidateMaxRunes = 600
	// 上游错误说明通常很短。
	upstreamErrorTextMaxRunes = 3000
)

// incompleteNarrationPattern 匹配「接下来式」叙述的最后一句：
// 模型说了要做什么却没有真的做（也未调用工具），此时不能当作结论。
var incompleteNarrationPattern = regexp.MustCompile(`(?i)^(let me|let's|i'll|i will|i am going to|i'm going to|now i|next[,: ]|then i|接下来|下面我|让我|随后|接着|现在我先|我先)`)

// markdownPrefixPattern 去掉行首的 markdown 前缀（标题/引用/列表项）。
var markdownPrefixPattern = regexp.MustCompile(`^\s*(?:#{1,6}\s+|>\s*|[-*+]\s+|\d{1,2}[.)、]\s+)*`)

// upstreamErrorTextMarkers 上游网关把错误说明写进 assistant 正文时的特征串（HTTP 200 + 错误文案）。
var upstreamErrorTextMarkers = []string{
	"ai provider temporarily unavailable",
	"request exceeded",
	"temporarily unavailable",
	"these responses are optimized for",
	"do not resend the same request",
	"minimum 1,000 prompt",
}

// looksLikeUpstreamErrorText 判断候选文本是否其实是上游错误说明而非模型回答。
// 结构性特征（网关会加 [req_xxx] [model] 前缀）优先；否则要求命中至少两个特征串。
func looksLikeUpstreamErrorText(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" || len([]rune(t)) > upstreamErrorTextMaxRunes {
		return false
	}
	lower := strings.ToLower(t)
	if strings.HasPrefix(lower, "[req_") {
		return true
	}
	hits := 0
	for _, marker := range upstreamErrorTextMarkers {
		if strings.Contains(lower, marker) {
			hits++
		}
	}
	return hits >= 2
}

// incompleteCandidateReason 判断候选最终文本是否是「没说完」的半截话，返回原因（空串表示看起来是完整回复）。
func incompleteCandidateReason(text string) string {
	t := strings.TrimSpace(text)
	if t == "" || len([]rune(t)) > incompleteCandidateMaxRunes {
		return ""
	}
	line := lastVisibleLine(t)
	if line == "" {
		return ""
	}
	if isNextStepNarration(lastSentence(line)) {
		return "candidate final text ends with a next-step narration instead of a delivered result"
	}
	if !hasTerminalPunctuation(line) {
		return "candidate final text looks cut off (no sentence-ending punctuation)"
	}
	return ""
}

// lastSentence 取一行文本的最后一句（按中英文句末标点切分），用于判断结尾是否是「接下来式」叙述。
func lastSentence(line string) string {
	parts := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case '。', '！', '？', '.', '!', '?', '\n':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

// lastVisibleLine 取最后一行有内容的文本，并去掉 markdown 前缀。
func lastVisibleLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		return strings.TrimSpace(markdownPrefixPattern.ReplaceAllString(line, ""))
	}
	return ""
}

// isNextStepNarration 判断这一行是否只是「接下来我要做 X」的自述。
func isNextStepNarration(line string) bool {
	return incompleteNarrationPattern.MatchString(strings.TrimSpace(line))
}

// hasTerminalPunctuation 判断行尾是否具备「句子/段落结束」的标点或收尾符号。
func hasTerminalPunctuation(line string) bool {
	s := strings.TrimRight(strings.TrimSpace(line), " \t")
	if s == "" {
		return false
	}
	runes := []rune(s)
	switch runes[len(runes)-1] {
	case '。', '！', '？', '.', '!', '?', '…',
		'）', ')', '】', ']', '》', '」', '』', '"', '\'', '”', '’', '`', '|':
		return true
	default:
		return false
	}
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
