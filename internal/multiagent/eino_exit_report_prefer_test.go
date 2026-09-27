package multiagent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/eino/schema"
)

// einoTestReport 生成一份「不同行内容互不重复」的类报告文本，避免触发去重逻辑。
func einoTestReport(n int) string {
	var b strings.Builder
	b.WriteString("## 结论\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "第 %d 项：发现条目 %d，证据编号 %d。\n", i, i*7+1, i*13+3)
	}
	return b.String()
}

func TestShouldPreferExitReport(t *testing.T) {
	report := einoTestReport(60)
	cases := []struct {
		name    string
		current string
		report  string
		want    bool
	}{
		{"正文为空则采用报告", "", report, true},
		{"正文只是过程性短片段则采用报告", "作者页只暴露了 admin 这个登录名，用户列表接口是 403。我再补匿名基线。", report, true},
		{"正文已足够长则保留正文", einoTestReport(40), report, false},
		{"报告过短不覆盖正文", "一段简短的过程文字", "简报", false},
		{"没有报告则保留正文", "一段简短的过程文字", "", false},
		{"长度接近则保留正文", strings.Repeat("y", 500), strings.Repeat("x", 600), false},
		{"增幅不足阈值则保留正文", strings.Repeat("y", 600), strings.Repeat("x", 700), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldPreferExitReport(tc.current, tc.report); got != tc.want {
				t.Fatalf("shouldPreferExitReport() = %v, want %v", got, tc.want)
			}
		})
	}
}

// 复现线上问题：监督者把过程性文字流成助手正文，正式报告只在 exit.final_result 里。
// 修复前该报告不会成为用户可见回复（网页上看不到、数据库里也没有这条消息）。
func TestBuildEinoRunResult_surfacesExitReportOverProgressFragment(t *testing.T) {
	report := einoTestReport(60)
	progress := "作者页只暴露了 admin 这个登录名，用户列表接口是 403。我再对文档和配置类接口做匿名基线。"
	msgs := []*schema.Message{
		schema.UserMessage("对 example.com 做全面、完整、深度测试"),
		toolExitMsg(report, "call-exit-1"),
	}
	out := buildEinoRunResultFromAccumulated("deep", msgs, msgs, progress, "", "empty hint", nil, false)
	if strings.TrimSpace(out.Response) != strings.TrimSpace(report) {
		t.Fatalf("期望回填 exit 报告，实际得到 %q", out.Response)
	}
}

// 模型已经自行输出了完整正文时，不能被 exit 摘要覆盖。
func TestBuildEinoRunResult_keepsLongAssistantText(t *testing.T) {
	report := einoTestReport(5)
	long := einoTestReport(40)
	msgs := []*schema.Message{
		schema.UserMessage("hi"),
		toolExitMsg(report, "call-exit-1"),
	}
	out := buildEinoRunResultFromAccumulated("deep", msgs, msgs, long, "", "empty hint", nil, false)
	if strings.TrimSpace(out.Response) != strings.TrimSpace(long) {
		t.Fatalf("长正文应被保留，实际得到 %q", out.Response)
	}
}

// 正文为空且存在 exit 报告时，保持既有兜底行为。
func TestBuildEinoRunResult_emptyAssistantStillUsesExitReport(t *testing.T) {
	report := einoTestReport(60)
	msgs := []*schema.Message{
		schema.UserMessage("hi"),
		toolExitMsg(report, "call-exit-1"),
	}
	out := buildEinoRunResultFromAccumulated("deep", msgs, msgs, "", "", "empty hint", nil, false)
	if strings.TrimSpace(out.Response) != strings.TrimSpace(report) {
		t.Fatalf("期望回填 exit 报告，实际得到 %q", out.Response)
	}
}
