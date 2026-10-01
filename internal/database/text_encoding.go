package database

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/mcp"
)

// toolExecutionText encodes bytes that PostgreSQL UTF-8 text cannot store as
// visible \\xHH escapes (lowercase hex). Valid UTF-8, including an actual U+FFFD,
// is kept verbatim. This is a persistence-only representation: never assign it
// back to the execution's raw output buffer, where the next streaming chunk may
// complete a currently incomplete UTF-8 sequence. Byte counts remain raw counts.
func toolExecutionText(raw string) string {
	if utf8.ValidString(raw) && strings.IndexByte(raw, 0) < 0 {
		return raw
	}

	const hex = "0123456789abcdef"
	var out strings.Builder
	out.Grow(len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		if raw[i] == 0 || (r == utf8.RuneError && size == 1) {
			out.WriteString(`\x`)
			out.WriteByte(hex[raw[i]>>4])
			out.WriteByte(hex[raw[i]&0xf])
		} else {
			out.WriteString(raw[i : i+size])
		}
		i += size
	}
	return out.String()
}

// marshalToolExecutionResult uses a copy so JSON encoding does not silently
// replace invalid output bytes with U+FFFD or mutate the model-facing result.
// Save and reduction updates must use the same persistence representation.
func marshalToolExecutionResult(result *mcp.ToolResult) ([]byte, error) {
	copyResult := *result
	if result.Content != nil {
		copyResult.Content = append([]mcp.Content{}, result.Content...)
		for i := range copyResult.Content {
			copyResult.Content[i].Type = toolExecutionText(copyResult.Content[i].Type)
			copyResult.Content[i].Text = toolExecutionText(copyResult.Content[i].Text)
		}
	}
	return json.Marshal(&copyResult)
}
