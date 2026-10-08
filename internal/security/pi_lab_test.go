package security

import (
	"net/http"
	"testing"
)

func TestPILabRoutesRequireAgentExecution(t *testing.T) {
	for _, path := range []string{"/pi-lab/status", "/pi-lab/runs", "/pi-lab/runs/:id", "/pi-lab/runs/:id/events", "/pi-lab/runs/:id/cancel"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if got := permissionForRequest(method, "/api"+path); got != "agent:execute" {
				t.Errorf("%s %s: %q", method, path, got)
			}
		}
	}
	if got := permissionForRequest(http.MethodGet, "/api/pi-lab/unmapped"); got != "" {
		t.Fatal("unknown PI routes must fail closed", got)
	}
}
