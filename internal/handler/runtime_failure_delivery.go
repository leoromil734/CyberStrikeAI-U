package handler

import (
	"context"
	"errors"
	"strings"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/multiagent"
)

// Runtime failure is still a reportable stopped run. Keep the HTTP error and
// assessment outcome while saving the same evidence-based report as SSE.
func (h *AgentHandler) persistRuntimeFailureForDelivery(ctx context.Context, conversationID, messageID, agentMode string, result *multiagent.RunResult, ids []string, runErr error, candidateReports ...string) agentfinalizer.Decision {
	status, reason := agentfinalizer.StatusFailed, agentfinalizer.ReasonFailed
	switch {
	case errors.Is(context.Cause(ctx), ErrTaskCancelled):
		status, reason = agentfinalizer.StatusCancelled, agentfinalizer.ReasonCancelled
	case errors.Is(runErr, context.DeadlineExceeded) || errors.Is(context.Cause(ctx), context.DeadlineExceeded):
		status, reason = "timeout", "timeout"
	case mcp.IsAgentRunBudgetReason(mcp.AgentRunBudgetStopReason(context.Cause(ctx))):
		status, reason = agentfinalizer.StatusBlocked, mcp.AgentRunBudgetStopReason(context.Cause(ctx))
	case errors.Is(runErr, context.Canceled):
		status, reason = agentfinalizer.StatusCancelled, agentfinalizer.ReasonCancelled
	}
	d := agentfinalizer.Decision{Status: status, CompletionReason: reason}
	if len(candidateReports) > 0 {
		d.CandidateReport = candidateReports[0]
	}
	reasoning := ""
	if result != nil {
		d.FinalText, d.ReportSubmitted = result.Response, result.ReportSubmitted
		if result.ReportSubmitted && strings.TrimSpace(result.SubmittedReport) != "" {
			d.FinalText = result.SubmittedReport
		}
		d.PendingExecutionIDs = append([]string(nil), result.PendingExecutionIDs...)
		d.MissingChecks = append([]string(nil), result.MissingChecks...)
		ids = mergeMCPExecutionIDLists(ids, result.MCPExecutionIDs)
		reasoning = multiagent.AggregatedReasoningFromTraceJSON(result.LastAgentTraceInput)
	}
	if runErr != nil {
		d.MissingChecks = append(d.MissingChecks, "runtime error: "+safeTruncateString(runErr.Error(), 1200))
	}
	return h.persistFinalizationDecision(conversationID, messageID, agentMode, ids, reasoning, d)
}
