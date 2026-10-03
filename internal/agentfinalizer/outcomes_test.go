package agentfinalizer

import "testing"

func TestExplicitRefusalsAreTerminalNotSuccessfulAssessments(t *testing.T) {
	for _, text := range []string{
		"这个请求不能做。对 example.com 做全面渗透属于未经授权的攻击，我不会进行扫描。",
		"我不能对 example.com 做全面渗透、资产测绘或漏洞利用。",
		"宝宝，这个我不能做。对 example.com 做漏洞挖掘属于未授权攻击。",
		"宝宝，这个我没法帮你做。example.com 是真实外部站点，我不能对它做渗透、扫描或漏洞利用。",
		"I cannot help perform a penetration test against this system.",
	} {
		d := Decide(nil, Input{Response: text, AgentMode: "batch", RequireExecutionEvidence: true})
		if d.Status != StatusDeclined || !d.Finalizable || d.EvidenceVerified || Outcome(d.Status, d.CompletionReason, d.FinalText) != "declined" {
			t.Fatalf("refusal misclassified: %q: %+v", text, d)
		}
	}
}

func TestReportsAndOrdinaryChatAreNotRefusals(t *testing.T) {
	for _, text := range []string{
		"本轮测试完成。我不能确认 SQL 注入，因为请求被 WAF 拦截。",
		"我不能对这条记录下结论，但可以查看原始证据。",
		"报告引用了‘我不能帮你进行攻击’，该引用不是执行结果。",
	} {
		if IsExplicitRefusal(text) {
			t.Fatalf("normal result classified as refusal: %q", text)
		}
	}
	d := Decide(nil, Input{Response: "我不能帮助进行攻击。", AgentMode: "chat"})
	if d.Status == StatusDeclined {
		t.Fatal("ordinary chat policy unexpectedly changed")
	}
}

func TestOutcomeDoesNotUpgradeLegacyDelivery(t *testing.T) {
	if Outcome(StatusCompleted, "", "legacy result") != "delivered" {
		t.Fatal("legacy delivery upgraded")
	}
	if Outcome(StatusCompleted, ReasonVerifiedWithLimits, "report") != "delivered_with_gaps" {
		t.Fatal("limitations lost")
	}
	if Outcome(StatusBlocked, ReasonPendingTools, "") != "tool_blocked" {
		t.Fatal("tool blocker lost")
	}
}
