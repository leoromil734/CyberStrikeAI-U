package projectprompt

import (
	"strings"
	"testing"
)

func TestExecutionCoverageIsPresentInAllPromptModes(t *testing.T) {
	for _, mode := range []PromptMode{PromptModeSingle, PromptModeDeep, PromptModeSupervisor, PromptModePlanExecute, PromptModeSubAgent} {
		t.Run(string(mode), func(t *testing.T) {
			prompt := ComposeSystemPrompt("custom role", mode)
			if strings.Count(prompt, ExecutionCoverageSection()) != 1 {
				t.Fatal("every mode and custom role must contain execution coverage exactly once")
			}
		})
	}
}

func TestBrandExpansionDistinguishesCDNFromHosting(t *testing.T) {
	for _, required := range []string{
		"有关联证据的疑似域名和 IP 都要测", "品牌扩测限任务范围", "Cloudflare/Akamai", "已证实 CDN 边缘 IP",
		"域名业务仍测", "Hetzner 等云/托管商不是 CDN", "范围内非 CDN IP 必须独立枚举",
		"CDN unknown 留 gap/blocked", "共享 IP/ASN 不证明品牌归属", "不扫供应商网段或无关租户",
	} {
		if !strings.Contains(ExecutionCoverageSection(), required) {
			t.Errorf("brand expansion missing %q", required)
		}
	}
}

func TestCredentialCoverageIsBoundedAndIncludesNonHTTP(t *testing.T) {
	for _, required := range []string{
		"SSH、数据库、SMTP/IMAP/POP3", "做一次简单弱口令尝试", "侦察角色识别后交接验证",
		"每账号≤8", "每入口≤5账号/40组合/5分钟", "并发1", "间隔≥3秒",
		"命中/验证码/MFA/锁定/429/异常即停", "不全量笛卡尔积", "缺身份/策略阻断记 blocked",
		"协议不支持口令可凭证据 N/A", "实际次数、字典 hash、停止原因",
	} {
		if !strings.Contains(ExecutionCoverageSection(), required) {
			t.Errorf("bounded credential coverage missing %q", required)
		}
	}
	if !strings.Contains(SkillsRoutingSection(), "弱口令/SSH/数据库/邮件认证") {
		t.Fatal("non-HTTP authentication must route to the credential skill")
	}
}

func TestJSRequiresToolAndSourceCommandEvidence(t *testing.T) {
	for _, required := range []string{
		"JS 必须双通道", "jsluice 静态分析本地 JS", "全部已下载 JS/chunk/worker/source map 原源码", "实际执行 grep/rg",
		"fetch/axios/XHR", "baseURL", "模板拼接与调用上下文", "raw/unique/incremental",
		"工具零结果不替代源码检索", "字符串命中不等于完整或可达", "缺任一路留 gap/blocked",
	} {
		if !strings.Contains(ExecutionCoverageSection(), required) {
			t.Errorf("JS extraction missing %q", required)
		}
	}
	for _, required := range []string{"工具+grep/rg 两路证据", "非 CDN IP 扩测", "SSH/数据库/邮件弱口令无未处理 gap", "有关联证据的疑似域名、源站 IP 已测或有证据 blocked"} {
		if !strings.Contains(CompletionContractSection(), required) {
			t.Errorf("completion gate missing %q", required)
		}
	}
}
