// Package targets 负责从用户输入中识别「本次要跑的目标域名」，并做统一归一化。
//
// 这里的规则是平台唯一的「什么算目标」判据：对话页提醒、任务管理提醒、运行开始时的
// 历史登记、以及历史回填都走同一份实现，避免各处各写一套正则而互相矛盾。
package targets

import (
	"regexp"
	"sort"
	"strings"
)

// candidateRe 匹配候选主机名：至少两段标签，最后一段是 2~24 位字母。
// 允许被汉字/标点包围（\b 只认 ASCII 词边界），因此「对hfm.com做…」也能命中。
var candidateRe = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b`)

// ipv4Re 用于剔除形如 1.2.3.4 的 IP（它们会被上面的正则匹配成 four-label 主机名）。
var ipv4Re = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

// hostRe 要求「整串就是一个主机名」。Normalize 用它而不是 candidateRe，
// 否则「对 orbex.com 做全面渗透」这种整句会被原样当成目标存进去。
var hostRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$`)

// nonTargetTLDs 是「看着像域名、实际是文件名」的常见后缀。
// 典型的踩坑：渗透脚本里的 poc.py、probe.sh、results.json 被误登记成目标。
// 这里只放本工作流里高频出现的扩展名，真实业务域名后缀（com/de/it/io/nl…）不受影响。
var nonTargetTLDs = map[string]struct{}{
	"py": {}, "js": {}, "mjs": {}, "cjs": {}, "ts": {}, "jsx": {}, "tsx": {}, "vue": {},
	"sh": {}, "bash": {}, "zsh": {}, "ps1": {}, "bat": {}, "cmd": {},
	"go": {}, "rs": {}, "java": {}, "rb": {}, "php": {}, "c": {}, "h": {}, "cpp": {}, "cs": {},
	"json": {}, "yaml": {}, "yml": {}, "toml": {}, "ini": {}, "conf": {}, "cfg": {},
	"txt": {}, "md": {}, "rst": {}, "log": {}, "out": {}, "err": {}, "csv": {}, "tsv": {},
	"html": {}, "htm": {}, "xml": {}, "css": {}, "map": {}, "sql": {}, "db": {}, "sqlite": {},
	"zip": {}, "tar": {}, "gz": {}, "tgz": {}, "bz2": {}, "xz": {}, "7z": {}, "jar": {},
	"exe": {}, "dll": {}, "bin": {}, "so": {}, "dylib": {}, "o": {}, "a": {},
	"pem": {}, "crt": {}, "cer": {}, "key": {}, "p12": {}, "pfx": {},
	"bak": {}, "tmp": {}, "temp": {}, "old": {}, "orig": {}, "swp": {}, "lock": {}, "sum": {},
	"ipynb": {}, "dat": {}, "pkl": {}, "sample": {}, "pcap": {}, "har": {},
}

// Normalize 把任意写法的目标归一到登记用的规范形式：
// 去掉协议/路径/查询串/端口、小写、去掉开头 www. 与结尾点。
// 传入空串或明显不是域名的输入时返回空串。
func Normalize(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// 去掉协议头（含 //host 形式）
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	// 去掉用户信息 user:pass@host
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	// 去掉路径/查询/片段
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	// 去掉端口（IPv6 字面量不处理，交给 IP 过滤）
	if idx := strings.LastIndex(s, ":"); idx >= 0 && !strings.Contains(s[idx:], "]") {
		s = s[:idx]
	}
	s = strings.Trim(s, " \t\r\n.,;:!?()[]{}<>\"'`*|\\")
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "www.")
	if s == "" || ipv4Re.MatchString(s) {
		return ""
	}
	if !hostRe.MatchString(s) {
		return ""
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return ""
	}
	tld := labels[len(labels)-1]
	if _, bad := nonTargetTLDs[tld]; bad {
		return ""
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return ""
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
	}
	return s
}

// Extract 从一段文本里提取所有目标域名，按首次出现顺序返回并去重。
// 结果已归一化，可直接入库或用于查重。
func Extract(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	matches := candidateRe.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		norm := Normalize(m)
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeAll 批量归一化并去重（保留输入顺序），用于把前端传来的目标列表统一成规范形式。
func NormalizeAll(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		norm := Normalize(item)
		if norm == "" {
			// 允许直接传纯文本（例如粘贴的整段任务描述）
			for _, nested := range Extract(item) {
				if _, ok := seen[nested]; ok {
					continue
				}
				seen[nested] = struct{}{}
				out = append(out, nested)
			}
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

// SortedCopy 返回排序后的副本，便于测试与稳定输出。
func SortedCopy(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}
