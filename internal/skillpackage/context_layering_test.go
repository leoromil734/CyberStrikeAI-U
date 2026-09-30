package skillpackage

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

// These hashes pin the complete original Git blobs at c0bb176, including front
// matter, whitespace and EOF. Windows core.autocrlf changes checkout EOLs, so
// the source-of-truth archive retains repository LF bytes rather than an
// environment-specific CRLF checkout. Do not normalize archive bytes here.
var contextLayeringBaselines = []struct {
	name        string
	sha256      string
	bytes       int
	gitBlobHash string
}{
	{"specialized-attack-playbooks", "de25635a4ca184e2b17c63090e2062d9c0d2f46ff351a91a760611adcbbed3b1", 12343, "dcac58927c03fe30c559c571b5050311c42a7a5e"},
	{"cdn-tls-fingerprint", "1681e84086fb993f88d4b58bc4e0625887b460f103e00eedfd7855fe7012a99d", 5473, "80a1587b926ab768d7df5bbdafdbb2621c952d84"},
}

func contextLayeringRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate context layering test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "skills"))
}

func contextLayeringRead(t *testing.T, root, name, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, name, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s/%s: %v", name, rel, err)
	}
	return raw
}

// Only content-move comparisons normalize EOLs. The raw archive hash test above
// remains strict, so text fidelity cannot accidentally stand in for byte fidelity.
func contextLayeringText(raw []byte) string {
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

func contextLayeringRequire(t *testing.T, source, body string, required ...string) {
	t.Helper()
	for _, phrase := range required {
		if !strings.Contains(body, phrase) {
			t.Errorf("%s missing layering condition %q", source, phrase)
		}
	}
}

func contextLayeringLine(t *testing.T, body, marker string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, marker) {
			return line
		}
	}
	t.Fatalf("missing route/decision line %q", marker)
	return ""
}

func contextLayeringExcerpt(t *testing.T, body, start, end string) string {
	t.Helper()
	at := strings.Index(body, start)
	if at < 0 {
		t.Fatalf("archive missing source marker %q", start)
	}
	rest := body[at:]
	until := strings.Index(rest[len(start):], end)
	if until < 0 {
		t.Fatalf("archive missing closing source marker %q after %q", end, start)
	}
	return strings.TrimSpace(rest[:len(start)+until])
}

func TestContextLayeringOriginalBaselines(t *testing.T) {
	root := contextLayeringRoot(t)
	for _, baseline := range contextLayeringBaselines {
		t.Run(baseline.name, func(t *testing.T) {
			raw := contextLayeringRead(t, root, baseline.name, "references/original-skill.md")
			if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != baseline.sha256 {
				t.Errorf("original archive SHA256 = %s, want pre-layering %s; preserve exact repository/EOF bytes", got, baseline.sha256)
			}
			if len(raw) != baseline.bytes {
				t.Errorf("original archive bytes = %d, want %d", len(raw), baseline.bytes)
			}
			blob := sha1.New()
			fmt.Fprintf(blob, "blob %d%c", len(raw), 0)
			blob.Write(raw)
			if got := fmt.Sprintf("%x", blob.Sum(nil)); got != baseline.gitBlobHash {
				t.Errorf("archive Git blob = %s, want original c0bb176 blob %s", got, baseline.gitBlobHash)
			}
			attributes := contextLayeringText(contextLayeringRead(t, root, baseline.name, ".gitattributes"))
			contextLayeringRequire(t, baseline.name+" attributes", attributes, "references/original-skill.md -text")
		})
	}
}

func TestContextLayeringMetadataAndEntryBudgets(t *testing.T) {
	root := contextLayeringRoot(t)
	for _, baseline := range contextLayeringBaselines {
		t.Run(baseline.name, func(t *testing.T) {
			entry := contextLayeringRead(t, root, baseline.name, "SKILL.md")
			archive := contextLayeringRead(t, root, baseline.name, "references/original-skill.md")
			original, oldBody, err := ParseSkillMD(archive)
			if err != nil {
				t.Fatalf("parse original: %v", err)
			}
			current, body, err := ParseSkillMD(entry)
			if err != nil {
				t.Fatalf("parse entry: %v", err)
			}
			if !reflect.DeepEqual(current, original) {
				t.Errorf("front matter changed; preserve name, description, metadata and allowed-tools: got %+v, want %+v", current, original)
			}
			if err := ValidateSkillMDPackage(entry, baseline.name); err != nil {
				t.Errorf("entry validation: %v", err)
			}
			if len(entry) >= len(archive) || utf8.RuneCountInString(body) >= utf8.RuneCountInString(oldBody) {
				t.Error("layered entry must be shorter in both bytes and body runes")
			}
			contextLayeringRequire(t, baseline.name+" entry", body, "references/original-skill.md", "必要时完整取回", "不默认加载")
			t.Logf("%s entry bytes %d -> %d (%.1f%% smaller); body runes %d -> %d",
				baseline.name, len(archive), len(entry), 100*(1-float64(len(entry))/float64(len(archive))),
				utf8.RuneCountInString(oldBody), utf8.RuneCountInString(body))
		})
	}
}

var contextLayeringPathPattern = regexp.MustCompile(`(?:references|scripts)/[A-Za-z0-9._/-]+\.(?:md|py|js)`)

func contextLayeringCheckPaths(dir, body string) error {
	for _, rel := range contextLayeringPathPattern.FindAllString(body, -1) {
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("missing routed file %s: %w", rel, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("routed path is not a regular file: %s", rel)
		}
	}
	return nil
}

func TestContextLayeringRoutedPathsExist(t *testing.T) {
	root := contextLayeringRoot(t)
	for _, baseline := range contextLayeringBaselines {
		body := contextLayeringText(contextLayeringRead(t, root, baseline.name, "SKILL.md"))
		if err := contextLayeringCheckPaths(filepath.Join(root, baseline.name), body); err != nil {
			t.Errorf("%s: %v", baseline.name, err)
		}
	}
	// The same checker must reject a plausible but unattached historical path,
	// and reject directories masquerading as a document.
	dir := t.TempDir()
	if err := contextLayeringCheckPaths(dir, "references/not-attached.md"); err == nil {
		t.Error("missing reference incorrectly accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "references"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "references", "directory.md"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := contextLayeringCheckPaths(dir, "references/directory.md"); err == nil {
		t.Error("directory reference incorrectly accepted")
	}
}

func TestContextLayeringSpecializedTopicsRetainFullTextAndRoutes(t *testing.T) {
	root := contextLayeringRoot(t)
	name := "specialized-attack-playbooks"
	entry := contextLayeringText(contextLayeringRead(t, root, name, "SKILL.md"))
	archiveRaw := contextLayeringRead(t, root, name, "references/original-skill.md")
	archive := contextLayeringText(archiveRaw)
	topics := []struct {
		file, direction, start, end string
		conditions                  []string
	}{
		{"goedge-cdn.md", "GoEdge CDN(8002端口)私钥批量导出", "### GoEdge CDN(8002端口)私钥批量导出", "\n### 灰产CDN后渗透取证", []string{"前提", "GoEdge API 指纹", "管理员 AK/SK", "token", "sslCertJSON", "keyData", "跨范围私钥证据", "MITM", "凭据复用", "边缘节点"}},
		{"cdn-post-access-forensics.md", "灰产CDN后渗透取证", "### 灰产CDN后渗透取证", "\n### ARP MITM", []string{"前提", "证书访问权限", "过期/禁用", "关键词", "重定向", "title/meta/h1/JS跳转", "重新分类", "A/B/C", "不能只信证书域名"}},
		{"arp-l2-mitm.md", "ARP MITM同L2窃取SSH密码", "### ARP MITM", "\n### 多层域名轮换", []string{"前提", "同L2", "同Hyper-V宿主/同VLAN", "已控跳板机", "目标SSH密码未知", "MAC", "验证", "通知", "清理", "持久化"}},
		{"cdn-antiblock-s3.md", "多层域名轮换CDN防封", "### 多层域名轮换", "\n### 宝塔面板", []string{"前提", "多层JS跳转", "Landing", "S3归属/bucket", "APK/API/AES", "JWT/STS", "对象写入单变量对照", "证据闭合"}},
		{"bt-panel.md", "宝塔面板(BT Panel)渗透", "=== 宝塔面板指纹识别 ===", "\n\n=== UniApp/DCloud", []string{"前提", "404 Set-Cookie", "32位MD5", "_ssl", "版本", "CVE-2023-38038仅<=7.7", "入口枚举", "同IP弱站横向", "随机8位不可推导", "2024+无已知通用绕过"}},
		{"uniapp-dcloud.md", "UniApp/DCloud APK逆向", "=== UniApp/DCloud APK逆向(极高效) ===", "\n\n=== 橙子建站", []string{"前提", "APK", "dcloud_uniplugins/assets/apps/uni-jsframework", "manifest", "config/env API", "业务/IDOR", "认证凭据", "加密/签名", "WebSocket", "实际后端证据"}},
		{"chengzi-sdk.md", "橙子建站(ChengZi/d3504.cn) SDK解密", "=== 橙子建站(ChengZi/d3504.cn) SDK解密 ===", "\n### AI IDE", []string{"前提", "APP分发/邀请/跳转", "init3", "URL-safe base64", "XOR 0x96", "fu/ph/fm", "APK/阿里云FC", "后端API", "不是可调用文件"}},
		{"ai-ide-api-proxy.md", "AI IDE API反代/key泄露目录", "### AI IDE API反代/key泄露目录", "\n### OCS在线客服", []string{"前提", "凭据暴露", "仓库搜索", "README", "最新issue", "可用", "已废", "辅助", "原文记录"}},
		{"ocs-minio.md", "OCS在线客服系统 + MinIO对象存储", "### OCS在线客服系统渗透 + MinIO对象存储利用", "\n## 支持文件索引", []string{"前提", "SPA真实API", "visitor token", "签名/上传", "静态对象", "dir/bucket", "MinIO版本", "CDN响应大小", "nginx方法/路径ACL", "Spring", "宝塔", "Longteng", "不等于Tomcat执行", "webroot/执行证据", "挑战通过不等于路径ACL通过"}},
	}
	if got := len(regexp.MustCompile(`(?m)^### .+$`).FindAllString(archive, -1)); got != 7 {
		t.Fatalf("original inline topic count = %d, want 7 (expanded into nine product/scenario routes)", got)
	}
	for _, topic := range topics {
		t.Run(topic.file, func(t *testing.T) {
			route := contextLayeringLine(t, entry, "references/"+topic.file)
			contextLayeringRequire(t, topic.file+" route", route, append([]string{topic.direction}, topic.conditions...)...)
			raw := contextLayeringRead(t, root, name, "references/"+topic.file)
			text := contextLayeringText(raw)
			excerpt := contextLayeringExcerpt(t, archive, topic.start, topic.end)
			if !strings.Contains(text, excerpt) {
				t.Error("routed reference does not contain the complete original topic/subtopic verbatim")
			}
			// References are self-contained; selecting a topic must not require
			// the archive or a second product's reference.
			for _, path := range contextLayeringPathPattern.FindAllString(text, -1) {
				if path == "scripts/chengzi_decrypt.py" && topic.file == "chengzi-sdk.md" {
					contextLayeringRequire(t, topic.file, text, "历史未附带素材", "本包没有该脚本", "不能作为调用入口")
					continue
				}
				t.Errorf("single-topic reference unexpectedly depends on %s", path)
			}
			if len(contextLayeringRead(t, root, name, "SKILL.md"))+len(raw) >= len(archiveRaw) {
				t.Error("entry plus one topic should remain smaller than the original all-inline entry")
			}
			t.Logf("selected topic %s: %d bytes, %d runes", topic.file, len(raw), utf8.RuneCount(raw))
		})
	}
	contextLayeringRequire(t, name+" entry", entry, "一个专题文件", "无需读取其他专题", "历史未附带素材", "索引只保留在原文归档", "不补造脚本", "不作为默认上下文",
		"发卡系统", "PHPCMS V9", "Spring Boot/Actuator", "CDN/WAF", "WebSocket/SockJS/STOMP", "nginx/PHP-FPM/PATH_INFO", "APK 逆向", "不能因缺参考文件而把该方向写成已测或已排除")
	for _, obsolete := range []string{"scripts/", "faka-system-attack-chain.md", "phpcms-v9-attack-surface.md", "spring-stomp-exploit.py", "cdn-antiblock-s3-attack-chain.md"} {
		if strings.Contains(entry, obsolete) {
			t.Errorf("entry advertises unattached historical material %q", obsolete)
		}
	}
	if got := len(contextLayeringPathPattern.FindAllString(entry, -1)); got != len(topics)+1 {
		t.Errorf("entry routes = %d, want nine topics plus one audit archive", got)
	}
}

func TestContextLayeringCDNDecisionEvidenceAndAlternatives(t *testing.T) {
	root := contextLayeringRoot(t)
	name := "cdn-tls-fingerprint"
	entry := contextLayeringText(contextLayeringRead(t, root, name, "SKILL.md"))
	contextLayeringRequire(t, name+" entry", entry,
		"受控对比", "不是将 `curl_cffi` 设为默认客户端", "单次403/429/503都不等于TLS指纹拦截",
		"同时满足", "同一请求低速重试", "挑战页、连接重置或非业务响应",
		"相同网络出口、同 URL、同方法和同认证态", "Cookie、Authorization、CSRF、请求体、Content-Type、必要 Header 和重定向",
		"已排除明显的 JS Challenge、验证码、速率限制、IP 信誉和地区限制",
		"仅 `httpx -cdn`", "`server: cloudflare`/`cf-ray`", "相同应用层401/403/404", "新Cookie/JS Challenge", "降速/换出口后恢复",
		"一次只改变一个变量", "URL / method / body", "network egress", "headers / cookies / auth", "redirect policy", "request rate", "client stack", "status / response markers / edge headers",
		"`tls_fingerprint_confirmed`", "`cookie_or_js_challenge`", "`rate_or_ip_block`", "`application_denial`", "`inconclusive`",
		"变量未对齐或结果不稳定", "不得宣称TLS指纹拦截", "Turnstile", "真实浏览器完成挑战",
		"Cookie绑定、出口IP、浏览器请求头", "不要反复更换 `impersonate` 猜测",
		"所有客户端稳定502", "路径规则、上游故障或反向代理，不归因TLS", "429或批量后全403", "降低并发/速率",
		"已授权且存在源站线索", "Host/SNI", "最小源站验证", "范围约束",
		"受影响的结论性请求", "同一个 `curl_cffi.Session`", "不用于普通探活、爬取或目录枚举", "`httpx`", "`ffuf`/`dirsearch`", "标准脚本",
		"Surface", "Diagnose", "Verify", "Record", "同一已验证可达客户端", "`edge_block`", "`app_403`", "`auth_fail`", "真实漏洞证据",
		"测试矩阵、响应标记、唯一变化变量和结论置信度", "不能证明“接口不存在”或“没有漏洞”", "存在CDN也不能证明必须使用curl_cffi",
		"references/curl-cffi-usage.md", "references/original-skill.md")
	branches := []struct {
		marker string
		want   []string
	}{
		{"S0 标准客户端低速基线", []string{"已到业务层", "停止，不使用 curl_cffi", "边缘拦截", "S1"}},
		{"S1 同条件真实浏览器", []string{"浏览器也被拦", "未确认TLS差分", "浏览器挑战/限流/IP诊断", "浏览器到业务层", "S2"}},
		{"S2 对齐 Cookie", []string{"认证、方法、请求体与重定向", "复测标准客户端", "恢复", "差异来自请求状态，不是TLS", "仍停在边缘", "S3"}},
		{"S3 安装并只发送 1 个 curl_cffi 诊断请求", []string{"curl_cffi到业务层、标准客户端仍在边缘", "唯一变化为客户端栈", "确认TLS/HTTP2客户端指纹", "仍挑战", "未确认", "真实浏览器", "挑战Cookie", "不循环猜测画像"}},
	}
	for _, branch := range branches {
		contextLayeringRequire(t, branch.marker, contextLayeringLine(t, entry, branch.marker), branch.want...)
	}
	conclusions := []struct {
		marker string
		want   []string
	}{
		{"`tls_fingerprint_confirmed`", []string{"同请求条件", "只有浏览器TLS栈/curl_cffi到业务层"}},
		{"`cookie_or_js_challenge`", []string{"挑战Cookie或执行JS后可达", "浏览器流程"}},
		{"`rate_or_ip_block`", []string{"降速/换出口后恢复", "限速/代理策略"}},
		{"`application_denial`", []string{"相同业务401/403", "鉴权/业务测试"}},
		{"`inconclusive`", []string{"变量未对齐或结果不稳定", "不得宣称TLS指纹拦截"}},
	}
	for _, conclusion := range conclusions {
		contextLayeringRequire(t, conclusion.marker, contextLayeringLine(t, entry, conclusion.marker), conclusion.want...)
	}
	archive := contextLayeringText(contextLayeringRead(t, root, name, "references/original-skill.md"))
	usage := contextLayeringText(contextLayeringRead(t, root, name, "references/curl-cffi-usage.md"))
	if !strings.Contains(usage, contextLayeringExcerpt(t, archive, "## 4. 确认后使用", "\n## 6. 与漏洞验证衔接")) {
		t.Error("usage reference lost original installation, script or detailed failure diagnostics")
	}
	contextLayeringRequire(t, "CDN usage", usage, "pip install curl_cffi", "install-python-package", "execute-python-script", "same-token-as-baseline", "same-cookie-as-baseline", "allow_redirects=False", "S3 仅发送一个诊断请求")
	if strings.Contains(entry, "pip install") || strings.Contains(entry, "session = requests.Session") {
		t.Error("installation/script examples should be in the on-demand reference, not the entry")
	}
}
