package vulnquality

import (
	"encoding/json"
	"os"
	"testing"
	"unicode/utf8"
)

// Optional offline regression against a private operator-selected saved tool
// argument file. It never prints evidence, executes code, or contacts a target.
func TestSavedRecordEvidenceCompatibility(t *testing.T) {
	path := os.Getenv("CYBERSTRIKE_SAVED_RECORD_ARGS")
	if path == "" {
		t.Skip("optional private saved-record fixture not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("saved-record fixture cannot be read")
	}
	var args map[string]interface{}
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatal("saved-record fixture is not a JSON object")
	}
	validation, missing := ParseBoundaryValidation(args)
	if len(missing) > 0 {
		t.Fatalf("boundary fields missing: %v", missing)
	}
	if err := ValidateBoundary(validation); err != nil {
		t.Fatalf("boundary validation: %v", err)
	}
	evidence, ok := args["evidence"].(string)
	if !ok {
		t.Fatal("evidence is not text")
	}
	if err := ValidateEvidencePOC(evidence); err != nil {
		t.Fatalf("saved evidence format rejected: %v", err)
	}
	t.Logf("saved evidence passed static boundary/format checks (%d runes); no script or request executed", utf8.RuneCountInString(evidence))
}
