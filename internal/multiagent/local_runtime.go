package multiagent

import "context"

func firstPrepareExecution(values []func(context.Context, string) context.Context) func(context.Context, string) context.Context {
	if len(values) > 0 {
		return values[0]
	}
	return nil
}
