package mcp

import "context"

const NativeCLIInvocationVersion = "native-cli/v1"

// ToolInvocation is host-generated execution metadata, never decoded from tool
// arguments, result text or remote MCP metadata. It is retained in the immutable
// ingestion snapshot; historical monitor rows without it stay legacy rows.
// Arguments on ToolExecution contain the resolved defaults/aliases at execution
// time, while Argv records the actual CLI options used for the output contract.
type ToolInvocation struct {
	Version      string   `json:"version"`
	ToolName     string   `json:"tool_name"`
	Argv         []string `json:"argv"`
	StdoutFormat string   `json:"stdout_format,omitempty"`
	MachineFile  string   `json:"machine_file,omitempty"`
	CaptureError string   `json:"capture_error,omitempty"`
}

type invocationRecorderKey struct{}
type invocationRecorder func(string, map[string]interface{}, *ToolInvocation) bool

// RecordToolInvocation accepts metadata only from trusted in-process executors.
// A JSON argument named invocation (or any similar host-looking field) cannot
// populate this channel. The callback is bound to the worker's own execution.
func RecordToolInvocation(ctx context.Context, tool string, args map[string]interface{}, invocation *ToolInvocation) bool {
	if ctx == nil {
		return false
	}
	record, _ := ctx.Value(invocationRecorderKey{}).(invocationRecorder)
	return record != nil && record(tool, args, invocation)
}

func cloneToolInvocation(in *ToolInvocation) *ToolInvocation {
	if in == nil {
		return nil
	}
	out := *in
	out.Argv = append([]string(nil), in.Argv...)
	return &out
}

func setToolInvocation(execution *ToolExecution, tool string, args map[string]interface{}, invocation *ToolInvocation) bool {
	if execution == nil || execution.ToolName != tool || isExecutionTerminal(execution.Status) || invocation == nil || invocation.ToolName != tool || invocation.Version != NativeCLIInvocationVersion {
		return false
	}
	execution.Arguments = cloneArgsMap(args)
	execution.Invocation = cloneToolInvocation(invocation)
	return true
}

// SetToolExecutionInvocation covers Begin/FinishToolExecution callers that do
// not run in ExecutionService. No new execution is created for an unknown ID.
func (s *Server) SetToolExecutionInvocation(id, tool string, args map[string]interface{}, invocation *ToolInvocation) bool {
	if s == nil || id == "" {
		return false
	}
	if s.executionService != nil {
		s.executionService.mu.Lock()
		entry := s.executionService.entries[id]
		ok := entry != nil && setToolInvocation(entry.exec, tool, args, invocation)
		s.executionService.mu.Unlock()
		if ok {
			return true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return setToolInvocation(s.executions[id], tool, args, invocation)
}
