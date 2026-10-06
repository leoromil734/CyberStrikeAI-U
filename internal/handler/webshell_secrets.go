package handler

import (
	"net/http"

	"cyberstrike-ai/internal/database"
)

func publicWebshellConnection(conn *database.WebShellConnection) *database.WebShellConnection {
	if conn == nil {
		return nil
	}
	public := *conn
	if public.Password != "" {
		public.Password = maskedSecret
	}
	return &public
}

// WebShell passwords can be in query strings or replayable POST bodies.
// Redirecting them to another destination would bypass connection/URL binding.
func webshellRejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
