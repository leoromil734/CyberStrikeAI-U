package vision

import (
	"context"

	"cyberstrike-ai/internal/config"
)

type sessionOpenAIConfigContextKey struct{}

// WithSessionOpenAIConfig binds the model endpoint, credential and model selected
// for the current Agent run. The value is copied so concurrent sessions never
// mutate or reuse another session's configuration.
func WithSessionOpenAIConfig(ctx context.Context, openAI config.OpenAIConfig) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sessionOpenAIConfigContextKey{}, openAI)
}

// SessionOpenAIConfigFromContext returns the exact OpenAI-compatible model
// configuration selected for the current Agent run.
func SessionOpenAIConfigFromContext(ctx context.Context) (config.OpenAIConfig, bool) {
	if ctx == nil {
		return config.OpenAIConfig{}, false
	}
	openAI, ok := ctx.Value(sessionOpenAIConfigContextKey{}).(config.OpenAIConfig)
	return openAI, ok
}
