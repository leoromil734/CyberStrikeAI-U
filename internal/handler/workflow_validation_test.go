package handler

import (
	"strings"
	"testing"
)

func TestValidWorkflowIDSecurity(t *testing.T) {
	for _, id := range []string{"workflow-1", "workflow_2", "工作流1", "0", strings.Repeat("a", 128)} {
		if !validWorkflowID(id) {
			t.Errorf("valid workflow ID %q rejected", id)
		}
	}
	for _, id := range []string{"", "../workflow", "a/b", `a\b`, "a.b", "_first", "-first", "a b", "a\nb", "a\x00b", strings.Repeat("a", 129), strings.Repeat("中", 43)} {
		if validWorkflowID(id) {
			t.Errorf("invalid workflow ID %q accepted", id)
		}
	}
}
