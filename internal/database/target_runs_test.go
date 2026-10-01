package database

import (
	"testing"
	"time"
)

func TestTargetRunsRecordCheckAndDelete(t *testing.T) {
	db := newTargetHistoryTestDB(t)

	convA, err := db.CreateConversation("对 hfm.com 做全面 完整 深度的渗透测试 漏洞挖掘", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	convB, err := db.CreateConversation("对 hfm.com 做全面 完整 深度的渗透测试 漏洞挖掘", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	recorded, err := db.RecordTargetRuns(convA.ID, convA.Title, "", []string{"对 hfm.com 做全面 完整 深度的渗透测试"}, time.Now())
	if err != nil {
		t.Fatalf("RecordTargetRuns: %v", err)
	}
	if recorded != 1 {
		t.Fatalf("首次登记应记录 1 个目标，得到 %d", recorded)
	}

	// 同一对话重复登记（多轮追问）不应把次数刷高。
	again, err := db.RecordTargetRuns(convA.ID, convA.Title, "", []string{"hfm.com"}, time.Now())
	if err != nil {
		t.Fatalf("RecordTargetRuns: %v", err)
	}
	if again != 0 {
		t.Fatalf("同对话重复登记应记 0，得到 %d", again)
	}

	hits, err := db.CheckTargetRuns([]string{"hfm.com", "orbex.com"})
	if err != nil {
		t.Fatalf("CheckTargetRuns: %v", err)
	}
	if len(hits) != 1 || hits[0].Target != "hfm.com" {
		t.Fatalf("只应命中 hfm.com，得到 %+v", hits)
	}
	if hits[0].RunCount != 1 {
		t.Fatalf("RunCount = %d, want 1", hits[0].RunCount)
	}
	if hits[0].LastConversationID != convA.ID {
		t.Fatalf("LastConversationID = %q, want %q", hits[0].LastConversationID, convA.ID)
	}

	// 第二个对话跑同一目标 → 次数 +1，「最近一次」指向新对话。
	if _, err := db.RecordTargetRuns(convB.ID, convB.Title, "", []string{"hfm.com"}, time.Now()); err != nil {
		t.Fatalf("RecordTargetRuns: %v", err)
	}
	hits, err = db.CheckTargetRuns([]string{"hfm.com"})
	if err != nil {
		t.Fatalf("CheckTargetRuns: %v", err)
	}
	if len(hits) != 1 || hits[0].RunCount != 2 {
		t.Fatalf("RunCount 应为 2，得到 %+v", hits)
	}
	if hits[0].LastConversationID != convB.ID {
		t.Fatalf("最近一次对话应为 %q，得到 %q", convB.ID, hits[0].LastConversationID)
	}

	listed, total, err := db.ListTargetRuns("hfm", 10, 0)
	if err != nil {
		t.Fatalf("ListTargetRuns: %v", err)
	}
	if total != 1 || len(listed) != 1 {
		t.Fatalf("搜索 hfm 应只有 1 条，得到 total=%d list=%d", total, len(listed))
	}
	if _, total, err = db.ListTargetRuns("", 10, 0); err != nil || total != 1 {
		t.Fatalf("不带关键字应返回 1 条，得到 total=%d err=%v", total, err)
	}

	events, eventsTotal, err := db.ListTargetRunEvents("hfm.com", 10, 0)
	if err != nil {
		t.Fatalf("ListTargetRunEvents: %v", err)
	}
	if eventsTotal != 2 || len(events) != 2 {
		t.Fatalf("应有 2 条运行明细，得到 total=%d list=%d", eventsTotal, len(events))
	}

	if err := db.DeleteTargetRun("hfm.com"); err != nil {
		t.Fatalf("DeleteTargetRun: %v", err)
	}
	if _, total, err = db.ListTargetRuns("", 10, 0); err != nil || total != 0 {
		t.Fatalf("删除后应无记录，得到 total=%d err=%v", total, err)
	}
	if _, eventsTotal, err = db.ListTargetRunEvents("hfm.com", 10, 0); err != nil || eventsTotal != 0 {
		t.Fatalf("删除后明细应为空，得到 total=%d err=%v", eventsTotal, err)
	}
}

func TestTargetRunsIgnoreNonTargetInput(t *testing.T) {
	db := newTargetHistoryTestDB(t)
	conv, err := db.CreateConversation("只做一件事：调用 fofa_search 工具一次", ConversationCreateMeta{})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	recorded, err := db.RecordTargetRuns(conv.ID, conv.Title, "", []string{
		`只做一件事：调用 fofa_search 工具一次，参数 query 为 ip="136.110.39.163"`,
		"python3 poc.py 输出到 results.json",
	}, time.Now())
	if err != nil {
		t.Fatalf("RecordTargetRuns: %v", err)
	}
	if recorded != 0 {
		t.Fatalf("非目标输入不应登记，得到 %d", recorded)
	}
}

func TestBackfillTargetRunsFromConversationsIsIdempotent(t *testing.T) {
	db := newTargetHistoryTestDB(t)

	titles := []string{
		"对 orbex.com 做全面 完整 深度的渗透测试 漏洞挖掘",
		"对 libertex.com 做全面 完整 深度的渗透测试 漏洞挖掘",
		"只做一件事：调用 fofa_search 工具一次",
	}
	for _, title := range titles {
		if _, err := db.CreateConversation(title, ConversationCreateMeta{}); err != nil {
			t.Fatalf("CreateConversation(%q): %v", title, err)
		}
	}

	first, err := db.BackfillTargetRunsFromConversations()
	if err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if first.Conversations != 3 || first.WithTargets != 2 {
		t.Fatalf("首次回填统计异常: %+v", first)
	}
	if first.EventsInserted != 2 || first.Targets != 2 {
		t.Fatalf("首次回填应登记 2 个目标: %+v", first)
	}

	second, err := db.BackfillTargetRunsFromConversations()
	if err != nil {
		t.Fatalf("Backfill(重跑): %v", err)
	}
	if second.EventsInserted != 0 {
		t.Fatalf("重复回填不应新增明细，得到 %d", second.EventsInserted)
	}
	if second.Targets != 2 {
		t.Fatalf("重复回填后目标数应仍为 2，得到 %d", second.Targets)
	}

	hits, err := db.CheckTargetRuns([]string{"orbex.com", "libertex.com"})
	if err != nil {
		t.Fatalf("CheckTargetRuns: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("回填后应命中 2 个目标，得到 %+v", hits)
	}
	for _, hit := range hits {
		if hit.RunCount != 1 {
			t.Fatalf("%s 的 RunCount 应为 1，得到 %d", hit.Target, hit.RunCount)
		}
		if hit.LastRunAt == nil {
			t.Fatalf("%s 缺少最近运行时间", hit.Target)
		}
	}
}
