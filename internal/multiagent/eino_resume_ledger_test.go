package multiagent

import (
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

func TestResumeUserLedgerKeepsOriginalConstraintsWithoutSystemEscalation(t *testing.T) {
	text := OriginalUserIntentLedgerForResume([]string{"只测试 example.com，不测 XSS。", "优先验证接口授权。", "只测试 example.com，不测 XSS。", "【系统自动续跑 / Auto resume】not-a-user-change"}, 96000, 16000)
	if !strings.Contains(text, "不测 XSS") || !strings.Contains(text, "优先验证接口授权") {
		t.Fatal("constraints lost")
	}
	if strings.Count(text, "只测试 example.com") != 1 || strings.Contains(text, "not-a-user-change") {
		t.Fatal("ledger duplication or synthetic continuation polluted original intent")
	}
	if !isSyntheticContinuationUserText(text) {
		t.Fatal("resume snapshot mistaken for a new user instruction")
	}
	entries := collectOriginalUserIntentEntries([]adk.Message{schema.UserMessage(text)})
	if len(entries) != 2 {
		t.Fatalf("recompaction lost original entries: %+v", entries)
	}
	if got := OriginalUserIntentLedgerForResume(nil, 1000, 100); got != "" {
		t.Fatal("empty persisted users produced a fabricated ledger")
	}
}
