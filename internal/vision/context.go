package vision

import (
	"context"

	"cyberstrike-ai/internal/config"
)

type sessionOpenAIConfigContextKey struct{}
type sessionVisionConfigContextKey struct{}

// WithSessionConfig snapshots both the selected channel and its effective vision
// configuration. A disabled channel cannot fall back to another channel's tool.
func WithSessionConfig(ctx context.Context, visionCfg config.VisionConfig, openAI config.OpenAIConfig) context.Context {
	ctx = WithSessionOpenAIConfig(ctx, openAI)
	return context.WithValue(ctx, sessionVisionConfigContextKey{}, visionCfg)
}

func SessionVisionConfigFromContext(ctx context.Context) (config.VisionConfig, bool) {
	if ctx == nil {
		return config.VisionConfig{}, false
	}
	visionCfg, ok := ctx.Value(sessionVisionConfigContextKey{}).(config.VisionConfig)
	return visionCfg, ok
}

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
