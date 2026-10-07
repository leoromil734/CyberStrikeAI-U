package security

import (
	"strings"
	"testing"
)

func TestMailTDCredentialsNeverEnterWorkspaceCommands(t *testing.T) {
	env := safeWorkspaceEnv([]string{"PATH=/usr/bin", "MAILTD_API_KEY=td_fixture_only", "MAILTD_API_KEY_FILE=/etc/cyberstrikeai/mailtd-api-key", "CSAI_EXECUTION_ID=fixture"}, "/workspace/.home", "/workspace/.tmp")
	for _, entry := range env {
		if strings.HasPrefix(entry, "MAILTD_") || strings.Contains(entry, "td_fixture_only") || strings.Contains(entry, "mailtd-api-key") {
			t.Fatal("provider credentials reached arbitrary shell tools")
		}
	}
}
