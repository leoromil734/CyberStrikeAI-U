package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/mcp"
)

// 命令重复执行抑制（Loop Engineering / 空转治理）
//
// 背景：续跑段里模型会反复执行同一条探测命令（例如同一条 curl 命中 404/401
// 或超时后不断重试），单批任务实测出现同一条命令重复 28 次、527 次无效重试的
// 空转。这类重复不产生新证据，却消耗预算并让停滞时钟反复被误判为“有活动”。
//
// 策略：同一会话内，完全相同的命令（按规范化后的 SHA256 指纹）一旦执行达到
// 阈值且最近若干次结果一致（稳定），后续重复执行直接拒绝并要求切换目标。
// 不稳定的命令（例如每次输出不同的爬取/枚举）不拦截，避免误伤真实工作。

const (
	// commandRepeatLimit 同一命令在同一会话内允许的稳定重复次数上限。
	commandRepeatLimit = 3
	// commandStabilityWindow 判定“结果稳定”只看最近这么多次执行。
	commandStabilityWindow = 2
	// commandRepeatTTL 超过此时长的历史记录不参与重复判定，避免长时间运行后误拦。
	commandRepeatTTL = 3 * time.Hour
	// commandRepeatMaxEntries 单个会话缓存的最大命令数，防止无限增长。
	commandRepeatMaxEntries = 2000
)

// commandRepeatRecord 记录单条命令在该会话内的历史执行指纹。
type commandRepeatRecord struct {
	mu       sync.Mutex
	entries  map[string]*commandFingerprintRecord
	lastSeen time.Time
}

type commandFingerprintRecord struct {
	count      int
	recentHash []string // 最近 commandStabilityWindow 次结果指纹
	lastResult string   // 最近一次结果摘要，用于拒绝时回显给模型
	lastAt     time.Time
}

// commandRepeatRegistry 全局按会话隔离的命令重复注册表。
type commandRepeatRegistry struct {
	mu       sync.Mutex
	sessions map[string]*commandRepeatRecord
}

var globalCommandRepeatRegistry = &commandRepeatRegistry{sessions: make(map[string]*commandRepeatRecord)}

func (r *commandRepeatRegistry) session(conversationID string) *commandRepeatRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.sessions[conversationID]
	if rec == nil {
		rec = &commandRepeatRecord{entries: make(map[string]*commandFingerprintRecord)}
		r.sessions[conversationID] = rec
	}
	rec.lastSeen = time.Now()
	// 简单回收：会话数超过阈值时清理最久未使用的若干会话。
	if len(r.sessions) > 256 {
		r.evictStaleSessionsLocked()
	}
	return rec
}

func (r *commandRepeatRegistry) evictStaleSessionsLocked() {
	now := time.Now()
	for id, rec := range r.sessions {
		if now.Sub(rec.lastSeen) > 2*commandRepeatTTL {
			delete(r.sessions, id)
		}
	}
}

// normalizeCommandFingerprintInput 归一化命令指纹：去除首尾空白与多余空白，
// 使语义相同的命令（如换行/多空格差异）命中同一指纹。
func normalizeCommandFingerprintInput(command string) string {
	fields := strings.Fields(strings.TrimSpace(command))
	return strings.Join(fields, " ")
}

// commandFingerprintOf 返回归一化命令的 SHA256 十六进制指纹。
func commandFingerprintOf(command string) string {
	sum := sha256.Sum256([]byte(normalizeCommandFingerprintInput(command)))
	return hex.EncodeToString(sum[:])
}

// commandResultFingerprintOf 由执行结果文本推导一个短指纹，用于判断结果是否稳定。
func commandResultFingerprintOf(resultText string) string {
	trimmed := strings.TrimSpace(resultText)
	if len(trimmed) > 512 {
		trimmed = trimmed[:512]
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])[:16]
}

// recordCommandRun 在命令执行完成后记录本次结果，供后续稳定性判定。
func recordCommandRun(ctx context.Context, command, resultText string) {
	conversationID := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if conversationID == "" || strings.TrimSpace(command) == "" {
		return
	}
	rec := globalCommandRepeatRegistry.session(conversationID)
	fp := commandFingerprintOf(command)
	resultFp := commandResultFingerprintOf(resultText)
	now := time.Now()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	entry := rec.entries[fp]
	if entry == nil {
		entry = &commandFingerprintRecord{}
		rec.entries[fp] = entry
	}
	entry.count++
	entry.lastAt = now
	entry.recentHash = append(entry.recentHash, resultFp)
	if len(entry.recentHash) > commandStabilityWindow {
		entry.recentHash = entry.recentHash[len(entry.recentHash)-commandStabilityWindow:]
	}
	if trimmed := strings.TrimSpace(resultText); len(trimmed) > 200 {
		entry.lastResult = trimmed[:200]
	} else {
		entry.lastResult = trimmed
	}
}

// enforceCommandRepeatGuard 是执行前的最终闸门：若命令已稳定重复达到上限则拒绝，
// 要求模型切换到库存中未测试的目标。返回拒绝文本与 true 表示应拦截。
func enforceCommandRepeatGuard(ctx context.Context, command string) (string, bool) {
	conversationID := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
	if conversationID == "" || strings.TrimSpace(command) == "" {
		return "", false
	}
	rec := globalCommandRepeatRegistry.session(conversationID)
	fp := commandFingerprintOf(command)
	now := time.Now()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	entry := rec.entries[fp]
	if entry == nil || entry.count < commandRepeatLimit || now.Sub(entry.lastAt) > commandRepeatTTL {
		return "", false
	}
	// 仅当最近若干次结果一致（稳定）时才拦截，避免误伤输出多变的真实枚举。
	if !recentResultsStable(entry.recentHash) {
		return "", false
	}
	reject := "错误: 该命令在本会话内已重复执行 " + itoa(entry.count) + " 次且结果稳定，系统已阻止继续空转。\n" +
		"不要再重复执行这条命令。最近结果摘要：" + entry.lastResult + "\n" +
		"请立即切换到发现库存（query_recon_inventory）中尚未测试的高价值 URL（带参数的接口、API、后台/上传/认证路径优先），或改用不同方法/参数验证新的攻击面。"
	return reject, true
}

func recentResultsStable(hashes []string) bool {
	if len(hashes) < commandStabilityWindow {
		// 样本不足时不拦截，保持保守。
		return false
	}
	for i := 1; i < len(hashes); i++ {
		if hashes[i] != hashes[0] {
			return false
		}
	}
	return true
}

// itoa 是 strconv.Itoa 的本地别名，避免额外导入。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}