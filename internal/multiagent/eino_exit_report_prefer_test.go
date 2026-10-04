package multiagent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

// einoTestReport avoids repeated lines so draft de-duplication is not involved.
func einoTestReport(n int) string {
	var b strings.Builder
	b.WriteString("## 结论\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "第 %d 项：发现条目 %d，证据编号 %d。\n", i, i*7+1, i*13+3)
	}
	return b.String()
}

func TestBuildEinoRunResultSubmittedReportWinsRegardlessOfLength(t *testing.T) {
	for _, draft := range []string{"", "本轮正在核对证据。", einoTestReport(80)} {
		report := "\n" + einoTestReport(5) + "\n"
		trace := []*schema.Message{schema.UserMessage("current request"), schema.AssistantMessage(draft, nil)}
		out := buildEinoRunResult("deep", trace, draft, "", "empty", nil, false,
			&einoReportSubmission{submitted: true, report: report})
		if !out.ReportSubmitted || out.SubmittedReport != report || out.Response != strings.TrimSpace(report) {
			t.Fatalf("submitted report lost to draft: %#v", out)
		}
		if out.LastAgentTraceOutput != out.Response || out.LastAgentTraceInput == "" {
			t.Fatal("report preference must retain the trace")
		}
		if out.Finalized || out.EvidenceVerified || out.Status == "completed" {
			t.Fatal("submission is not coverage verification or finalization")
		}
	}
}

func TestBuildEinoRunResultHistoryCannotSubmit(t *testing.T) {
	report := einoTestReport(30)
	trace := []*schema.Message{schema.UserMessage("current request"), historicalExitMsg(report, "old-exit")}
	out := buildEinoRunResult("deep", trace, "current draft", "", "empty", nil, false, nil)
	if out.ReportSubmitted || out.SubmittedReport != "" || out.Response != "current draft" {
		t.Fatalf("history was promoted into a submission: %#v", out)
	}
	out = buildEinoRunResult("deep", trace, "", "", "empty", nil, false, nil)
	if out.Response != "empty" || out.ReportSubmitted {
		t.Fatalf("empty live output resurrected an old exit: %#v", out)
	}
}

func TestBuildEinoRunResultSubmittedOriginalIsNotDeduplicatedOrTruncated(t *testing.T) {
	report := strings.Repeat("原始提交内容不能被去重或丢失。\n\n", 9000)
	out := buildEinoRunResult("deep", nil, einoTestReport(40), "", "empty", nil, false,
		&einoReportSubmission{submitted: true, report: report})
	if !out.ReportSubmitted || out.SubmittedReport != report {
		t.Fatal("submitted original was modified")
	}
	if !strings.Contains(out.Response, "响应已截断") || !strings.HasPrefix(report, strings.Split(out.Response, "\n\n... (response truncated")[0]) {
		t.Fatal("display may be bounded, but must use the actual submitted report")
	}
}

func TestBuildEinoRunResultEmptySubmissionDoesNotResurrectDraft(t *testing.T) {
	out := buildEinoRunResult("deep", nil, einoTestReport(30), "", "empty", nil, false,
		&einoReportSubmission{submitted: true})
	if !out.ReportSubmitted || out.SubmittedReport != "" || out.Response != "empty" {
		t.Fatalf("empty exit incorrectly reused a draft: %#v", out)
	}
}
