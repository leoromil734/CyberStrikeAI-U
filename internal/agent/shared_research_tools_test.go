package agent

import "testing"

func TestSharedResearchToolsOnlyAllowExactPublicHelpers(t *testing.T) {
	for _, key := range []string{
		"web-search::web_search", "web-search::web_fetch", "web-search::github_readme",
		"web-search::research_plan", "web-search::proxy_status", "web-search::proxy_get",
		"web-search::proxy_rotate", "web-search::proxy_release", "web-search::proxy_healthcheck",
	} {
		if !isSharedResearchTool(key) {
			t.Errorf("shared helper %q should be available to specialized roles", key)
		}
	}
	for _, key := range []string{"web-search::exec", "other::web_search", "web_search", "web-search__proxy_get", "web-search::", "web-search::proxy_get::exec"} {
		if isSharedResearchTool(key) {
			t.Errorf("unrelated tool %q must remain role-scoped", key)
		}
	}
}
