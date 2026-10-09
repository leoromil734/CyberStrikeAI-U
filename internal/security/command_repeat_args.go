package security

import "strings"

// parseLiteralToolArgs is the executor's existing additional_args parser, shared
// with repeat admission. It is not a shell interpreter: repeat admission first
// checks simpleRepeatCommand and declines ambiguous syntax.
func parseLiteralToolArgs(argsStr string, shellLiterals bool) []string {
	if argsStr == "" {
		return []string{}
	}

	result := make([]string, 0)
	var current strings.Builder
	inQuotes := false
	var quoteChar rune
	escapeNext := false
	started := false

	runes := []rune(argsStr)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}

		if r == '\\' && !(shellLiterals && inQuotes && quoteChar == '\'') {
			if i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\'') {
				i++
				current.WriteRune(runes[i])
			} else {
				escapeNext = true
				current.WriteRune(r)
			}
			continue
		}

		if !inQuotes && (r == '"' || r == '\'') {
			started = true
			inQuotes = true
			quoteChar = r
			continue
		}

		if inQuotes && r == quoteChar {
			inQuotes = false
			quoteChar = 0
			continue
		}

		if !inQuotes && (r == ' ' || r == '\t' || r == '\n') {
			if current.Len() > 0 || (shellLiterals && started) {
				result = append(result, current.String())
				current.Reset()
			}
			started = false
			continue
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 || (shellLiterals && started) {
		result = append(result, current.String())
	}
	if len(result) == 0 {
		result = strings.Fields(argsStr)
	}
	return result
}
