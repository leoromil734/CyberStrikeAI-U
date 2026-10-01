package coverage

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var ledgerAssignmentStart = regexp.MustCompile(`^[a-z][a-z0-9_]*\s*=`)
var ledgerFieldName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func markdownLedgerField(line string) (string, bool) {
	if line != strings.TrimLeft(line, " \t") || !(strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ")) {
		return "", false
	}
	candidate := strings.TrimSpace(line[2:])
	key, _, ok := strings.Cut(candidate, ":")
	return candidate, ok && ledgerFieldName.MatchString(key)
}

// parseLedgerAssignmentHeader recognizes only the first non-empty line. Later
// prose containing semicolons/equals signs remains literal YAML field content.
// The header is removed without changing line numbers and merged after YAML
// parsing, so duplicate keys cannot override identity or completion metadata.
func parseLedgerAssignmentHeader(lines []string) (map[string]any, error) {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !ledgerAssignmentStart.MatchString(trimmed) {
			return nil, nil
		}
		parts, err := splitLedgerAssignments(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid assignment header (line %d): %w; use body_fields", i+1, err)
		}
		fields := make(map[string]any)
		for _, part := range parts {
			key, value, ok := strings.Cut(part, "=")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if !ok || !ledgerFieldName.MatchString(key) || value == "" {
				return nil, fmt.Errorf("invalid assignment header field %q (line %d): expected key=value; use body_fields", key, i+1)
			}
			if _, duplicate := fields[key]; duplicate {
				return nil, fmt.Errorf("duplicate assignment header field %s (line %d)", key, i+1)
			}
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(value), &node); err != nil {
				return nil, fmt.Errorf("invalid assignment header field %s (line %d): %w; use body_fields", key, i+1, err)
			}
			if len(node.Content) != 1 || node.Content[0].Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("invalid assignment header field %s (line %d): only scalar values are supported; use body_fields", key, i+1)
			}
			scalar := node.Content[0]
			var decoded any
			if scalar.Tag == "!!timestamp" {
				decoded = scalar.Value // retain the supplied date, not a time-zone conversion
			} else if err := scalar.Decode(&decoded); err != nil {
				return nil, fmt.Errorf("invalid assignment header field %s (line %d): %w", key, i+1, err)
			}
			fields[key] = decoded
		}
		lines[i] = ""
		return fields, nil
	}
	return nil, nil
}

// Semicolons delimit assignments only outside a quoted scalar. Quotes are
// recognized at the start of a value, not apostrophes inside plain prose.
func splitLedgerAssignments(line string) ([]string, error) {
	var parts []string
	start := 0
	var quote byte
	hasEquals, valueStarted := false, false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quote != 0 {
			if quote == '"' && ch == '\\' {
				i++
				continue
			}
			if ch == quote {
				if quote == '\'' && i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		if ch == ';' {
			parts = append(parts, line[start:i])
			start, hasEquals, valueStarted = i+1, false, false
			continue
		}
		if !hasEquals && ch == '=' {
			hasEquals = true
			continue
		}
		if hasEquals && !valueStarted && ch != ' ' && ch != '\t' {
			valueStarted = true
			if ch == '\'' || ch == '"' {
				quote = ch
			}
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted value")
	}
	if last := strings.TrimSpace(line[start:]); last != "" {
		parts = append(parts, last)
	}
	return parts, nil
}
