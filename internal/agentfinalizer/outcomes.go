package agentfinalizer

import (
	"regexp"
	"strings"
)

const (
	StatusDeclined           = "declined"
	ReasonDeclined           = "declined"
	ReasonVerifiedWithLimits = "verified_with_limitations"
)

// A refusal is a valid terminal reply, but never a successful assessment.
// Only short, explicit first-person refusals are classified. Reports and quoted
// tool output must not be relabelled as the model's own refusal.
var refusalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)^(?:[\s#*]|(?:宝宝|抱歉|很抱歉)[，,。:：\s])*我(?:不能|无法|不会|没法)(?:帮你|帮助你|协助你)?(?:对|提供|进行|执行|帮助|协助|做|帮).{0,180}(?:渗透|扫描|攻击|侦察|资产测绘|漏洞(?:挖掘|利用)|这个请求|这个任务)`),
	regexp.MustCompile(`(?is)^(?:[\s#*]|宝宝[，,。:：\s])*(?:这个|此)(?:请求|任务|我)(?:.{0,12})(?:不能做|不能帮|没法帮).{0,220}(?:渗透|扫描|攻击|未授权|外部站点)`),
	regexp.MustCompile(`(?is)^[\s#*]*(?:sorry[,， ]+)?(?:I (?:cannot|can't|won't|will not|am unable to)|I'm unable to).{0,160}(?:assist|help|perform|conduct|scan|attack|penetration|exploit)`),
}

func IsExplicitRefusal(text string) bool {
	text = strings.TrimSpace(text)
	if len([]rune(text)) > 1800 || strings.HasPrefix(text, ">") {
		return false
	}
	for _, pattern := range refusalPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// Outcome describes delivery separately from transport/lifecycle success.
// Unknown legacy results are never upgraded to verified completion.
func Outcome(status, reason, response string) string {
	if status == StatusDeclined || reason == ReasonDeclined || (status == StatusCompleted && IsExplicitRefusal(response)) {
		return "declined"
	}
	if status == StatusCompleted {
		if reason == ReasonVerifiedWithLimits {
			return "delivered_with_gaps"
		}
		if reason == ReasonVerified {
			return "verified_complete"
		}
		return "delivered"
	}
	if reason == ReasonPendingTools {
		return "tool_blocked"
	}
	if reason == ReasonMissingEvidence {
		return "no_execution_evidence"
	}
	return status
}
