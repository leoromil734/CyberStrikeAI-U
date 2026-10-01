package agent

// isSharedResearchTool makes the project's public-search and on-demand proxy
// helpers available to specialized roles. Server/tool enable flags and RBAC
// authorization still apply later; unrelated external tools remain role-scoped.
func isSharedResearchTool(toolKey string) bool {
	switch toolKey {
	case "web-search::web_search", "web-search::web_fetch", "web-search::github_readme",
		"web-search::research_plan", "web-search::proxy_status", "web-search::proxy_get",
		"web-search::proxy_rotate", "web-search::proxy_release", "web-search::proxy_healthcheck":
		return true
	default:
		return false
	}
}
