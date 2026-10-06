package handler

import "unicode"

// New workflow IDs must be safe identifiers. Existing IDs remain editable by
// their original route so this check does not rename historical definitions.
func validWorkflowID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i, r := range id {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !(i > 0 && (r == '_' || r == '-')) {
			return false
		}
	}
	return true
}
