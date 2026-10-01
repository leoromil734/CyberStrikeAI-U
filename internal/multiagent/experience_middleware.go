package multiagent

import (
	"context"
	"encoding/json"
	"strings"

	"cyberstrike-ai/internal/agent"

	"github.com/cloudwego/eino/compose"
)

// Capture argument parsing failures that happen before the MCP execution
// service. Other failures already have execution records and are not duplicated.
func experienceArgumentFailureMiddleware(ag *agent.Agent) compose.ToolMiddleware {
	record := func(ctx context.Context, input *compose.ToolInput, err error) {
		if ag == nil || input == nil || err == nil || !isSoftRecoverableToolError(err) {
			return
		}
		var decoded map[string]interface{}
		if json.Unmarshal([]byte(input.Arguments), &decoded) == nil {
			return
		}
		ag.RecordLocalToolExecution(ctx, strings.ReplaceAll(input.Name, "__", "::"), map[string]interface{}{"_unparsed_arguments": input.Arguments}, "", err)
	}
	return compose.ToolMiddleware{
		Invokable: func(next compose.InvokableToolEndpoint) compose.InvokableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.ToolOutput, error) {
				out, err := next(ctx, input)
				record(ctx, input, err)
				return out, err
			}
		},
		Streamable: func(next compose.StreamableToolEndpoint) compose.StreamableToolEndpoint {
			return func(ctx context.Context, input *compose.ToolInput) (*compose.StreamToolOutput, error) {
				out, err := next(ctx, input)
				record(ctx, input, err)
				return out, err
			}
		},
	}
}
