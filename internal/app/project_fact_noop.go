package app

import (
	"strings"

	"cyberstrike-ai/internal/database"
)

// An exact same-conversation retry changes neither facts nor provenance. Links
// use their own mutation contract; never silently discard an explicit links edit.
func projectFactMutationIsNoop(existing, next *database.ProjectFact, args map[string]interface{}) bool {
	if existing == nil || next == nil || existing.SourceConversationID != next.SourceConversationID {
		return false
	}
	if _, links := args["links"]; links {
		return false
	}
	if existing.FactKey != next.FactKey || existing.Summary != strings.TrimSpace(next.Summary) {
		return false
	}
	for _, v := range [][2]string{{next.Category, existing.Category}, {next.Body, existing.Body}, {next.Confidence, existing.Confidence}} {
		if strings.TrimSpace(v[0]) != "" && strings.TrimSpace(v[0]) != v[1] {
			return false
		}
	}
	if _, set := args["pinned"]; set && next.Pinned != existing.Pinned {
		return false
	}
	if _, set := args["related_vulnerability_id"]; set && next.RelatedVulnerabilityID != existing.RelatedVulnerabilityID {
		return false
	}
	return true
}
