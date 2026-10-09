package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/mcp"
)

const (
	commandRepeatLimit       = 3
	commandStabilityWindow   = 2
	commandRepeatTTL         = 3 * time.Hour
	commandRepeatMaxEntries  = 2000
	commandRepeatMaxSessions = 256
	httpRepeatLimit          = 5
)

// A single mutex protects lookup, expiry, admission and completion. In particular,
// concurrent calls reserve HTTP attempts before dispatch, not after responses arrive.
// Live HTTP counters are never evicted to make room: cache pressure fails closed
// for new HTTP identities, rather than silently restoring a spent allowance.
type commandRepeatRegistry struct {
	mu       sync.Mutex
	sessions map[string]*commandRepeatRecord
	now      func() time.Time
}

type commandRepeatRecord struct {
	entries  map[string]*commandFingerprintRecord
	targets  map[string]*httpRepeatRecord
	lastSeen time.Time
}

type commandFingerprintRecord struct {
	count      int
	recentHash []string
	lastResult string
	lastAt     time.Time
}

type httpRepeatRecord struct {
	count    int
	inFlight int
	lastAt   time.Time
}

var globalCommandRepeatRegistry = &commandRepeatRegistry{sessions: make(map[string]*commandRepeatRecord)}

func (r *commandRepeatRegistry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *commandRepeatRegistry) sessionLocked(id string, now time.Time, create bool) *commandRepeatRecord {
	for key, rec := range r.sessions {
		if now.Sub(rec.lastSeen) < commandRepeatTTL {
			continue
		}
		active := false
		for _, target := range rec.targets {
			active = active || target.inFlight > 0
		}
		if !active {
			delete(r.sessions, key)
		}
	}
	rec := r.sessions[id]
	if rec == nil && create && len(r.sessions) < commandRepeatMaxSessions {
		rec = &commandRepeatRecord{entries: make(map[string]*commandFingerprintRecord), targets: make(map[string]*httpRepeatRecord)}
		if r.sessions == nil {
			r.sessions = make(map[string]*commandRepeatRecord)
		}
		r.sessions[id] = rec
	}
	if rec != nil {
		for key, entry := range rec.entries {
			if now.Sub(entry.lastAt) >= commandRepeatTTL {
				delete(rec.entries, key)
			}
		}
		for key, entry := range rec.targets {
			if entry.inFlight == 0 && now.Sub(entry.lastAt) >= commandRepeatTTL {
				delete(rec.targets, key)
			}
		}
		rec.lastSeen = now
	}
	return rec
}

// Only collapse horizontal whitespace in a simple literal command. Preserve
// quoted bytes exactly. Scripts, escapes, substitutions, comments and shell
// operators fall back to byte identity (including Python/heredoc indentation).
func normalizeCommandFingerprintInput(command string) string {
	if normalized, ok := simpleRepeatCommand(command); ok {
		return normalized
	}
	return command
}

func simpleRepeatCommand(command string) (string, bool) {
	var out strings.Builder
	var quote byte
	space := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == '\n' || c == '\r' || c == 0 || (c == '\\' && quote != '\'') {
			return "", false
		}
		if quote != '\'' && (c == '$' || c == '`') {
			return "", false
		}
		if quote != 0 {
			out.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if strings.ContainsRune(";&|<>()#", rune(c)) {
			return "", false
		}
		if c == ' ' || c == '\t' {
			space = out.Len() > 0
			continue
		}
		if space {
			out.WriteByte(' ')
			space = false
		}
		if c == '\'' || c == '"' {
			quote = c
		}
		out.WriteByte(c)
	}
	return out.String(), quote == 0
}

func commandFingerprintOf(command string) string {
	return repeatHash(normalizeCommandFingerprintInput(command))
}

func repeatHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func recordCommandRun(ctx context.Context, command, resultText string) {
	recordCommandFingerprint(ctx, command, commandResultFingerprintOf(resultText), resultText)
}

func recordCommandFingerprint(ctx context.Context, command, fingerprint, preview string) {
	id := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if id == "" || strings.TrimSpace(command) == "" || fingerprint == "" {
		return
	}
	r := globalCommandRepeatRegistry
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	rec := r.sessionLocked(id, now, true)
	if rec == nil {
		return // Best-effort stability history; HTTP admission is separately fail-closed.
	}
	fp := commandFingerprintOf(command)
	entry := rec.entries[fp]
	if entry == nil {
		if len(rec.entries) >= commandRepeatMaxEntries {
			var oldest string
			for key, value := range rec.entries {
				if oldest == "" || value.lastAt.Before(rec.entries[oldest].lastAt) {
					oldest = key
				}
			}
			delete(rec.entries, oldest)
		}
		entry = &commandFingerprintRecord{}
		rec.entries[fp] = entry
	}
	entry.count++
	entry.lastAt = now
	entry.recentHash = append(entry.recentHash, fingerprint)
	if len(entry.recentHash) > commandStabilityWindow {
		entry.recentHash = entry.recentHash[len(entry.recentHash)-commandStabilityWindow:]
	}
	entry.lastResult = fmt.Sprintf("%.200s", strings.TrimSpace(preview))
}

// Stability is an additional early stop, not a substitute for the unconditional
// five-attempt HTTP allowance. Different results must never be identified by a
// prefix-only hash.
func enforceCommandRepeatGuard(ctx context.Context, command string) (string, bool) {
	id := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if id == "" || strings.TrimSpace(command) == "" {
		return "", false
	}
	r := globalCommandRepeatRegistry
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.sessionLocked(id, r.clock(), false)
	if rec == nil {
		return "", false
	}
	entry := rec.entries[commandFingerprintOf(command)]
	if entry == nil || entry.count < commandRepeatLimit || !recentResultsStable(entry.recentHash) {
		return "", false
	}
	return "错误: 该命令在本会话内已重复执行 " + itoa(entry.count) + " 次且结果稳定，系统已阻止继续空转。\n" +
		"最近结果摘要：" + entry.lastResult + "\n" + repeatGuardGuidance, true
}

const repeatGuardGuidance = "请立即切换到发现库存（query_recon_inventory）中尚未测试的高价值 URL，或改用不同方法/参数验证新的攻击面。此拦截不代表测试完成，仍需提交已取得的证据、未测缺口与最终报告。"

func recentResultsStable(hashes []string) bool {
	if len(hashes) < commandStabilityWindow || hashes[0] == "" {
		return false
	}
	for _, hash := range hashes[1:] {
		if hash != hashes[0] {
			return false
		}
	}
	return true
}

func itoa(n int) string { return strconv.Itoa(n) }

func repeatGuardToolResult(err error) *mcp.ToolResult {
	return &mcp.ToolResult{IsError: true, Content: []mcp.Content{{Type: "text", Text: err.Error()}}}
}

func acquireNativeCommandRepeatGuard(ctx context.Context, command string) (func(), error) {
	if reject, blocked := enforceCommandRepeatGuard(ctx, command); blocked {
		return func() {}, fmt.Errorf("%s", reject)
	}
	return AcquireHTTPRepeatGuard(ctx, "execute", map[string]interface{}{"command": command})
}

// AcquireHTTPRepeatGuard must run exactly once at actual dispatch, after any
// concurrency queue. release only unpins the entry; failed/empty responses still
// consume attempts. It uses trusted conversation context, never model arguments.
func AcquireHTTPRepeatGuard(ctx context.Context, toolName string, args map[string]interface{}) (func(), error) {
	noop := func() {}
	id := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if id == "" {
		return noop, nil
	}
	requests, err := repeatHTTPRequests(toolName, args)
	if err != nil || len(requests) == 0 {
		return noop, err
	}
	if err := ctx.Err(); err != nil {
		return noop, err
	}
	r := globalCommandRepeatRegistry
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	rec := r.sessionLocked(id, now, true)
	if rec == nil {
		return noop, fmt.Errorf("重复执行保护缓存已满，请等待历史会话过期；%s", repeatGuardGuidance)
	}
	newEntries := 0
	for key, cost := range requests {
		entry := rec.targets[key]
		count := 0
		if entry == nil {
			newEntries++
		} else {
			count = entry.count
		}
		if cost > httpRepeatLimit-count {
			return noop, fmt.Errorf("错误: 同一会话的 HTTP 目标已使用 %d/%d 次额度，本次需 %d 次；已在执行前阻止重复请求（不依赖响应是否相同）。%s", count, httpRepeatLimit, cost, repeatGuardGuidance)
		}
	}
	if len(rec.targets)+newEntries > commandRepeatMaxEntries {
		return noop, fmt.Errorf("重复执行保护缓存已满，请等待历史目标过期；%s", repeatGuardGuidance)
	}
	entries := make([]*httpRepeatRecord, 0, len(requests))
	for key, cost := range requests {
		entry := rec.targets[key]
		if entry == nil {
			entry = &httpRepeatRecord{}
			rec.targets[key] = entry
		}
		entry.count += cost
		entry.inFlight++
		entry.lastAt = now
		entries = append(entries, entry)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			now := r.clock()
			for _, entry := range entries {
				entry.inFlight--
				entry.lastAt = now
			}
			rec.lastSeen = now
		})
	}, nil
}
