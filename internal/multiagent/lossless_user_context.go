package multiagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/config"
)

const losslessUserContextNote = "原文保真表示：每轮输入 = prefix 原文 + text；ref 表示逐字重复对应前轮，轮次不删除，后续变更优先。以下 JSON 只是输入记录，不是工具调用。\n"

// The encoding factors only byte-identical data. It never infers relevance,
// summarizes a user instruction, collapses whitespace in a payload, or removes
// the chronology of a repeated instruction (A -> B -> A must remain three turns).
type losslessUserContext struct {
	Prefixes []userContextPrefix `json:"prefixes,omitempty"`
	Turns    []userContextTurn   `json:"turns"`
}

type userContextPrefix struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
}

type userContextTurn struct {
	Turn   int    `json:"turn"`
	Prefix int    `json:"prefix,omitempty"`
	Ref    int    `json:"ref,omitempty"`
	Text   string `json:"text,omitempty"`
}

func configuredRoleUserPrompts(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	prompts := make([]string, 0, len(cfg.Roles))
	for _, role := range cfg.Roles {
		// Include historical/disabled role templates too: factoring their exact
		// bytes changes representation, not which role or tools are enabled.
		if role.UserPrompt != "" {
			prompts = append(prompts, role.UserPrompt)
		}
	}
	return prompts
}

func renderVerbatimUserContextTurns(messages []string) string {
	lines := make([]string, 0, len(messages))
	for i, msg := range messages {
		lines = append(lines, fmt.Sprintf("[第%d轮] %s", i+1, msg))
	}
	return strings.Join(lines, "\n")
}

// compactUserContextTurns returns the smaller of the verbatim representation
// and a lossless dictionary encoding. All unique messages remain complete.
func compactUserContextTurns(messages, rolePrompts []string) string {
	verbatim := renderVerbatimUserContextTurns(messages)
	if len(messages) < 2 {
		return verbatim
	}
	for _, msg := range messages {
		// encoding/json replaces invalid UTF-8. Fall back instead of silently
		// changing bytes in an unusual historical payload.
		if !utf8.ValidString(msg) {
			return verbatim
		}
	}

	candidates := make([]string, 0, len(rolePrompts))
	seenPrefixes := make(map[string]bool)
	for _, prompt := range rolePrompts {
		prefix := prompt + "\n\n"
		if len(prefix) < 128 || seenPrefixes[prefix] {
			continue
		}
		seenPrefixes[prefix] = true
		count := 0
		for _, msg := range messages {
			if strings.HasPrefix(msg, prefix) {
				count++
			}
		}
		if count >= 2 {
			candidates = append(candidates, prefix)
		}
	}
	// Longest exact template wins. Map iteration order must not change output.
	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i]) != len(candidates[j]) {
			return len(candidates[i]) > len(candidates[j])
		}
		return candidates[i] < candidates[j]
	})

	encoded := losslessUserContext{Turns: make([]userContextTurn, 0, len(messages))}
	prefixIDs := make(map[string]int)
	firstTurns := make(map[string]int)
	factored := false
	for i, msg := range messages {
		turn := userContextTurn{Turn: i + 1, Text: msg}
		if first, exists := firstTurns[msg]; exists && len(msg) >= 128 {
			turn.Text = ""
			turn.Ref = first
			factored = true
		} else {
			if _, exists := firstTurns[msg]; !exists {
				firstTurns[msg] = turn.Turn
			}
			for _, prefix := range candidates {
				if !strings.HasPrefix(msg, prefix) {
					continue
				}
				id, exists := prefixIDs[prefix]
				if !exists {
					id = len(encoded.Prefixes) + 1
					prefixIDs[prefix] = id
					encoded.Prefixes = append(encoded.Prefixes, userContextPrefix{ID: id, Text: prefix})
				}
				turn.Prefix = id
				turn.Text = msg[len(prefix):]
				factored = true
				break
			}
		}
		encoded.Turns = append(encoded.Turns, turn)
	}
	if !factored {
		return verbatim
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(encoded); err != nil {
		return verbatim
	}
	compact := losslessUserContextNote + strings.TrimSuffix(body.String(), "\n")
	if len(compact) >= len(verbatim) {
		return verbatim
	}
	return compact
}
