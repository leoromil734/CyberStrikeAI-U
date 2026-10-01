package agent

import (
	"context"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/projectprompt"
)

func (a *Agent) SetExperienceHints(provider func(context.Context, []mcp.Tool) string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.experienceHints = provider
}

// ExperienceInstruction is built per authenticated task, never cached globally.
// Respect role tool allowlists: omit hints when the detail/search tools are absent.
func (a *Agent) ExperienceInstruction(ctx context.Context, defs []Tool) string {
	a.mu.RLock()
	provider := a.experienceHints
	tools := make([]mcp.Tool, 0, len(defs))
	search, get := false, false
	for _, d := range defs {
		name := d.Function.Name
		if name == builtin.ToolSearchExperience {
			search = true
		}
		if name == builtin.ToolGetExperience {
			get = true
		}
		if original, ok := a.toolNameMapping[name]; ok {
			name = original
		}
		tools = append(tools, mcp.Tool{Name: name})
	}
	a.mu.RUnlock()
	if provider == nil || !search || !get {
		return ""
	}
	return projectprompt.ExperienceMemorySection() + provider(ctx, tools)
}
