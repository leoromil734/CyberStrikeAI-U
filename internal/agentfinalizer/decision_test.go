package agentfinalizer

import "testing"

// libertex 会话的真实最终文本：模型只说了「接下来我去看看 X」就停了，必须判为未收敛。
const libertexIncompleteCandidate = "Recorded (vuln 4b44f555, medium). Let me check `/v1/captcha` and `/v1/registration` — whether the account-creation path is CAPTCHA-gated."

// 上游网关以 HTTP 200 返回的错误正文（18751e1e 会话真实内容）。
const upstreamErrorCandidate = `[req_d2c40afc] [deepseek-v4.1-flash-hc]
**Request exceeded 570s limit**
- Your prompt took too long to process, likely due to a large context window or heavy reasoning required by the AI provider.
How to fix:
- **Send "continue"** to resume from where the model stopped (works for most timeouts).`

func TestDecideBlocksUpstreamErrorText(t *testing.T) {
	d := Decide(nil, Input{Response: upstreamErrorCandidate, Status: StatusCompleted})
	if d.Finalizable || d.Finalized {
		t.Fatalf("上游错误正文不应可交付: %+v", d)
	}
	if d.Status != StatusFailed {
		t.Fatalf("status = %q, want %q", d.Status, StatusFailed)
	}
	if d.CompletionReason != ReasonUpstreamErrorText {
		t.Fatalf("reason = %q, want %q", d.CompletionReason, ReasonUpstreamErrorText)
	}
}

func TestDecideBlocksIncompleteCandidate(t *testing.T) {
	d := Decide(nil, Input{Response: libertexIncompleteCandidate, Status: StatusCompleted})
	if d.Finalizable || d.Finalized {
		t.Fatalf("半截话不应可交付: %+v", d)
	}
	if d.CompletionReason != ReasonIncompleteCandidate {
		t.Fatalf("reason = %q, want %q", d.CompletionReason, ReasonIncompleteCandidate)
	}
	if d.Status != StatusInProgress {
		t.Fatalf("status = %q, want %q", d.Status, StatusInProgress)
	}
}

func TestDecideBlocksStandaloneNarrationTail(t *testing.T) {
	// 结尾一句仍是「接下来我会…」这类自述：说明本轮没有真正收尾。
	d := Decide(nil, Input{Response: "已确认 hfm.com 三个入口匿名均 401。接下来我会继续验证 /api/secure-assets 的路径穿越。", Status: StatusCompleted})
	if d.Finalizable {
		t.Fatalf("以「接下来我会…」结尾的短候选不应可交付: %+v", d)
	}
	if d.CompletionReason != ReasonIncompleteCandidate {
		t.Fatalf("reason = %q, want %q", d.CompletionReason, ReasonIncompleteCandidate)
	}
}

func TestDecideBlocksCandidateWithoutTerminalPunctuation(t *testing.T) {
	d := Decide(nil, Input{Response: "已确认 my.hfm.com 的 /api/trader/* 全为 401，下一步准备测试 /api/secure-assets", Status: StatusCompleted})
	if d.Finalizable {
		t.Fatalf("缺句末标点的短候选不应可交付: %+v", d)
	}
	if d.CompletionReason != ReasonIncompleteCandidate {
		t.Fatalf("reason = %q, want %q", d.CompletionReason, ReasonIncompleteCandidate)
	}
}

func TestDecideAcceptsCompleteShortAnswer(t *testing.T) {
	d := Decide(nil, Input{Response: "my.hfm.com 的 /api/trader/* 与 /api/secure-assets 匿名均为 401，未发现可跨边界的匿名访问面。", Status: StatusCompleted})
	if !d.Finalizable || !d.Finalized {
		t.Fatalf("完整短回复应可交付: %+v", d)
	}
	if d.CompletionReason != ReasonVerified {
		t.Fatalf("reason = %q, want %q", d.CompletionReason, ReasonVerified)
	}
}

func TestDecideAcceptsLongReport(t *testing.T) {
	long := "## wealthify.com 全面深度渗透测试 — 结论报告\n\n**目标**：wealthify.com\n\n"
	for i := 0; i < 60; i++ {
		long += "- 覆盖项与证据说明，包含足够长度以超过短候选阈值，避免误判为半截话；此处继续补充说明文字用于测试。\n"
	}
	long += "\n### 未闭合面\n认证态结论为 blocked（缺测试身份）。" // 结尾有句号，长文本不参与完整性判定
	d := Decide(nil, Input{Response: long, Status: StatusCompleted})
	if !d.Finalizable {
		t.Fatalf("长报告应可交付: %+v", d)
	}
}

func TestDecideLongReportEndingMidSentenceStillDeliverable(t *testing.T) {
	// 超过阈值的长文本不做完整性判定，避免把正常长报告误判成半截话。
	long := ""
	for i := 0; i < 60; i++ {
		long += "覆盖项说明文字，用于超过短候选阈值。"
	}
	long += "最后一句没有句末标点"
	d := Decide(nil, Input{Response: long, Status: StatusCompleted})
	if !d.Finalizable {
		t.Fatalf("长文本不应因缺少句末标点被拦: %+v", d)
	}
}
