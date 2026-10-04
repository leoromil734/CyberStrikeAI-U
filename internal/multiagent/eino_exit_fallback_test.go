package multiagent

import (
	"testing"

	"cyberstrike-ai/internal/einomcp"

	"github.com/cloudwego/eino/schema"
)

func toolExitMsg(content, callID string) *schema.Message {
	return schema.ToolMessage(content, callID, schema.WithToolName("exit"))
}

func historicalExitMsg(content, callID string) *schema.Message {
	m := toolExitMsg(content, callID)
	m.Extra = map[string]any{rootExitReportExtraKey: true}
	return m
}

func TestEinoExtractFallbackAssistantFromMsgsDraftBoundaries(t *testing.T) {
	cases := []struct {
		name string
		msgs []*schema.Message
		want string
	}{
		{"root exit draft", []*schema.Message{schema.UserMessage("current"), historicalExitMsg("report", "old-exit")}, "report"},
		{"latest exit draft", []*schema.Message{schema.UserMessage("current"), historicalExitMsg("first", "one"), historicalExitMsg("second", "two")}, "second"},
		{"ordinary assistant draft", []*schema.Message{schema.UserMessage("current"), schema.AssistantMessage("draft", nil)}, "draft"},
		{"unscoped child or legacy exit", []*schema.Message{schema.UserMessage("current"), toolExitMsg("unscoped", "one")}, ""},
		{"failed exit", []*schema.Message{schema.UserMessage("current"), historicalExitMsg(einomcp.ToolErrorPrefix+"failed report", "one")}, ""},
		{"unexecuted arguments", []*schema.Message{schema.UserMessage("current"), submissionToolCall("one", "exit", `{"final_result":"unexecuted"}`)}, ""},
		{"new request boundary", []*schema.Message{schema.UserMessage("old"), historicalExitMsg("old report", "one"), schema.UserMessage("new")}, ""},
		{"internal repair preserves draft", []*schema.Message{schema.UserMessage("current"), historicalExitMsg("report", "one"), schema.UserMessage(CoverageContinuationHeader)}, "report"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := einoExtractFallbackAssistantFromMsgs(tc.msgs); got != tc.want {
				t.Fatalf("draft=%q, want %q", got, tc.want)
			}
			out := buildEinoRunResult("deep", tc.msgs, "", "", "empty", nil, false, nil)
			if out.ReportSubmitted || out.SubmittedReport != "" || out.Response != "empty" {
				t.Fatal("historical fallback must not become a runtime submission")
			}
		})
	}
}
