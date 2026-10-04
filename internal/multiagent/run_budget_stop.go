package multiagent

import (
	"context"
	"cyberstrike-ai/internal/mcp"
)

// A service budget stop is an incomplete assessment, not a user cancellation or
// a successful model report. Keep the resumable trace and already captured IDs.
func applyRunBudgetStop(ctx context.Context, result *RunResult, err error) (*RunResult, error) {
	if ctx == nil {
		return result, err
	}
	cause := context.Cause(ctx)
	reason := mcp.AgentRunBudgetStopReason(cause)
	if reason == "" {
		return result, err
	}
	if result == nil {
		result = &RunResult{}
	}
	result.Status = "blocked"
	result.CompletionReason = reason
	result.Finalized = false
	result.EvidenceVerified = false
	result.Response = cause.Error()
	result.LastAgentTraceOutput = result.Response
	result.MissingChecks = append(result.MissingChecks, result.Response)
	return result, nil
}
