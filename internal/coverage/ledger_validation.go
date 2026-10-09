package coverage

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var ledgerErrorLine = regexp.MustCompile(`line ([0-9]+)`)

// ledgerKind limits the machine contract to actual ledger records. Free-form
// recon/note and recon/asset evidence must not become YAML completion gates.
func ledgerKind(key string) string {
	parts := strings.Split(key, "/")
	if len(parts) < 3 || parts[0] != "recon" {
		return ""
	}
	if oneOf(parts[1], "assessment", "phase", "source", "js", "endpoint", "risk") {
		return parts[1]
	}
	return ""
}

func ledgerNamespaceID(key string) string {
	parts := strings.Split(key, "/")
	kind := ledgerKind(key)
	minimum := 4
	if kind == "assessment" {
		minimum = 3
	} else if kind == "source" {
		minimum = 5 // legacy source/{tool}/{target} has no assessment namespace
	}
	if kind == "" || len(parts) < minimum || !assessmentIDPattern.MatchString(parts[2]) {
		return ""
	}
	return parts[2]
}

// ParseLedgerBody accepts JSON/YAML/Markdown fields and a scalar key=value header.
// The human-readable relationship mirror is not part of the machine object.
// Syntax errors retain line/field diagnostics; evidence/counts are never guessed.
func ParseLedgerBody(body string) (map[string]any, error) {
	body = strings.TrimSpace(body)
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			lines[i] = "" // keep source line numbers stable
		}
	}
	header, err := parseLedgerAssignmentHeader(lines)
	if err != nil {
		return nil, err
	}
	// Only a root Markdown field list uses bullet prefixes as object fields.
	// In ordinary YAML, an unindented sequence beneath phases: is valid and
	// must not be flattened into unrelated top-level properties.
	markdownFields := false
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			_, markdownFields = markdownLedgerField(line)
			break
		}
	}
	if markdownFields {
		for i, line := range lines {
			if field, ok := markdownLedgerField(line); ok {
				lines[i] = field
			}
		}
	}
	normalized := strings.Join(lines, "\n")
	trimmed := strings.TrimSpace(normalized)
	if strings.HasPrefix(trimmed, "{") {
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("invalid JSON object: %v; use body_fields instead of manually concatenating ledger text", err)
		}
		tail := strings.TrimSpace(trimmed[decoder.InputOffset():])
		if tail != "" && !strings.HasPrefix(tail, "## 关联\n") && tail != "## 关联" {
			return nil, fmt.Errorf("unexpected text after JSON ledger object; use separate fields or the relationship mirror")
		}
		normalized = string(raw)
	}
	var fields map[string]any
	if err := yaml.Unmarshal([]byte(normalized), &fields); err != nil {
		field := "body"
		lineNumber := 0
		if match := ledgerErrorLine.FindStringSubmatch(err.Error()); len(match) == 2 {
			lineNumber, _ = strconv.Atoi(match[1])
			if lineNumber > 0 && lineNumber <= len(lines) {
				if key, _, ok := strings.Cut(strings.TrimSpace(lines[lineNumber-1]), ":"); ok && key != "" && !strings.ContainsAny(key, " /\t") {
					field = key
				}
			}
		}
		return nil, fmt.Errorf("invalid YAML field %s (line %d): %v; quote strings containing '@' or ': ', or use body_fields", field, lineNumber, err)
	}
	if fields == nil && header != nil {
		fields = make(map[string]any)
	}
	for key, value := range header {
		if _, duplicate := fields[key]; duplicate {
			return nil, fmt.Errorf("duplicate ledger field %s in assignment header and YAML body", key)
		}
		fields[key] = value
	}
	if fields == nil {
		return nil, fmt.Errorf("ledger body must be an object")
	}
	return fields, nil
}

// ValidateLedgerFact checks the write contract, not completion of the whole
// assessment. Intermediate states remain writable. Legacy/free-form facts are
// left compatible; versioned records are rejected before any database mutation.
func ValidateLedgerFact(key, body string) error {
	kind := ledgerKind(key)
	if kind == "" {
		return nil
	}
	namespace := ledgerNamespaceID(key)
	fields, err := parseBody(body)
	if err != nil {
		if namespace == "" {
			return nil // unversioned legacy note; it cannot silently pass a v2 gate
		}
		return fmt.Errorf("%s: %w", key, err)
	}
	id := text(fields, "assessment_id")
	if namespace == "" && id == "" && kind != "assessment" {
		return nil
	}
	if !assessmentIDPattern.MatchString(id) {
		return fmt.Errorf("%s: assessment_id must be a valid lowercase assessment identifier", key)
	}
	if namespace != "" && namespace != id {
		return fmt.Errorf("%s: assessment_id does not match its namespace", key)
	}
	var problems []string
	requireText := func(names ...string) {
		for _, name := range names {
			if text(fields, name) == "" {
				problems = append(problems, name+" must be a non-empty string")
			}
		}
	}
	requireEvidence := func(name string) {
		if !meaningful(text(fields, name)) {
			problems = append(problems, name+" must contain concrete evidence/details")
		}
	}
	requireCount := func(name string, required bool) {
		_, present := fields[name]
		if (required || present) && number(fields, name) < 0 {
			problems = append(problems, name+" must be a non-negative integer (approximate text such as 30+ is not an integer)")
		}
	}
	status := text(fields, "status")
	switch kind {
	case "assessment":
		if key != "recon/assessment/"+id || number(fields, "schema_version") != 2 || text(fields, "mode") != "comprehensive" {
			problems = append(problems, "manifest requires schema_version: 2, mode: comprehensive and a matching key")
		}
		if !oneOf(status, "active", "completed") {
			problems = append(problems, "status must be active or completed")
		}
		// Scope is still required for completion and cannot be inferred. Inventory
		// counts are optional legacy metadata: Check derives them from its fact
		// snapshot, so concurrent ledger writes cannot stale a model-owned count.
		_, hasScope := fields["scope_kind"]
		if (hasScope || status == "completed") && !oneOf(text(fields, "scope_kind"), "root-domain", "single-url", "ip", "asset-list") {
			problems = append(problems, "scope_kind must describe the authorized scope")
		}
		for _, name := range []string{"endpoint_count", "js_count", "risk_unit_count"} {
			requireCount(name, false)
		}
	case "source":
		requireText("tool", "target")
		if !oneOf(status, "pending", "active", "gap", "covered", "blocked", "not-applicable") {
			problems = append(problems, "invalid source status")
		}
		terminal := oneOf(status, "covered", "blocked", "not-applicable")
		for _, name := range []string{"raw", "unique", "incremental"} {
			requireCount(name, terminal)
		}
		if raw, unique, incremental := number(fields, "raw"), number(fields, "unique"), number(fields, "incremental"); raw >= 0 && unique >= 0 && incremental >= 0 && (unique > raw || incremental > unique) {
			problems = append(problems, "counts must satisfy incremental <= unique <= raw")
		}
		if terminal {
			requireEvidence("evidence")
		}
		if status == "blocked" {
			requireEvidence("error")
			if !hasAlternatives(fields) {
				problems = append(problems, "alt_tried must contain attempted alternatives or explain their unavailability")
			}
		}
		if status == "not-applicable" {
			requireEvidence("reason")
		}
	case "phase":
		phase := key[strings.LastIndex(key, "/")+1:]
		if !oneOf(phase, phases...) {
			problems = append(problems, "invalid assessment phase")
		}
		if !oneOf(status, "pending", "active", "passed", "blocked") {
			problems = append(problems, "invalid phase status")
		}
		if oneOf(status, "passed", "blocked") {
			requireEvidence("evidence")
		}
		if status == "blocked" {
			requireEvidence("blockers")
		}
	case "js":
		if !oneOf(status, "queued", "fetched", "analyzed", "expanded", "blocked") {
			problems = append(problems, "invalid JS resource status")
		}
		if oneOf(status, "expanded", "blocked") {
			requireEvidence("evidence")
		}
		if status == "blocked" {
			requireEvidence("blockers")
		}
	case "endpoint":
		state := text(fields, "runtime_status")
		if !oneOf(state, "discovered", "extracted", "baselined", "risk-mapped", "verified", "negated", "blocked") {
			problems = append(problems, "invalid endpoint runtime_status")
		}
		if oneOf(state, "baselined", "risk-mapped", "verified", "negated", "blocked") {
			requireText("host", "method", "path")
			requireEvidence("evidence")
		}
		if state == "blocked" {
			requireEvidence("blockers")
		}
		if oneOf(state, "risk-mapped", "verified", "negated") && len(list(fields, "risk_units")) == 0 {
			problems = append(problems, "risk_units must list applicable assessment units")
		}
	case "risk":
		requireText("endpoint_key", "risk_family", "identity")
		if !oneOf(status, "pending", "active", "tentative", "gap", "waiting", "covered", "negated", "blocked", "not-applicable") {
			problems = append(problems, "invalid risk unit status")
		}
		if oneOf(status, "covered", "negated", "blocked", "not-applicable") {
			requireEvidence("evidence")
		}
		if oneOf(status, "blocked", "not-applicable") {
			requireEvidence("reason")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s: %s", key, strings.Join(problems, "; "))
	}
	return nil
}
