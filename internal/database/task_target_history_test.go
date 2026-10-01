package database

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func newTargetHistoryTestDB(t *testing.T) *DB {
	t.Helper()
	db := newRBACTestDB(t)
	if err := db.initTaskTargetHistory(); err != nil {
		t.Fatal(err)
	}
	return db
}

func targetHistoryConversation(t *testing.T, db *DB, title, message, owner, project string) *Conversation {
	t.Helper()
	conv, err := db.CreateConversation(title, ConversationCreateMeta{ProjectID: project})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("conversation", conv.ID, owner); err != nil {
		t.Fatal(err)
	}
	if message != "" {
		if _, err := db.AddMessage(conv.ID, "user", message, nil); err != nil {
			t.Fatal(err)
		}
	}
	return conv
}

func targetHistoryQueue(t *testing.T, db *DB, id, owner string, at time.Time) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO batch_task_queues (id, title, role, owner_user_id, status, created_at)
		VALUES (?, ?, ?, ?, 'pending', ?)`, id, "被截断的标题", "角色模板中的 template.example.com", owner, at); err != nil {
		t.Fatal(err)
	}
}

func targetHistoryTask(t *testing.T, db *DB, id, queue, message, conversation string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO batch_tasks (id, queue_id, message, conversation_id, status)
		VALUES (?, ?, ?, ?, 'pending')`, id, queue, message, conversation); err != nil {
		t.Fatal(err)
	}
}

func TestTaskTargetRegistrationsPendingAndRunCounts(t *testing.T) {
	db := newTargetHistoryTestDB(t)
	at := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	for _, fixture := range []struct {
		queue, task string
		want        int
	}{
		{"q1", "t1", 1}, {"q1", "t1", 0}, {"q1", "t2", 1}, {"q2", "t3", 1},
	} {
		n, err := db.RecordTaskTargets(fixture.queue, fixture.task, "测试 https://WWW.HFM.COM/a 与 hfm.com；poc.py results.json 192.0.2.1", "", "u1", at)
		if err != nil || n != fixture.want {
			t.Fatalf("record %s/%s: n=%d want=%d err=%v", fixture.queue, fixture.task, n, fixture.want, err)
		}
	}
	hits, err := db.CheckTargetRunsForAccess([]string{"hfm.com", "poc.py", "results.json", "192.0.2.1"}, "u1", RBACScopeOwn)
	if err != nil || len(hits) != 1 {
		t.Fatalf("pending hits=%+v err=%v", hits, err)
	}
	hit := hits[0]
	if hit.RunCount != 0 || hit.SubmittedCount != 3 || hit.FirstRunAt != nil || hit.LastRunAt != nil || hit.LastConversationID != "" {
		t.Fatalf("submissions were treated as runs: %+v", hit)
	}
	if hit.LastSubmittedAt == nil || !hit.LastSubmittedAt.Equal(at) || hit.LastQueueID != "q2" || hit.LastTaskID != "t3" {
		t.Fatalf("missing submission metadata: %+v", hit)
	}
	var aggregateCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM target_runs").Scan(&aggregateCount); err != nil || aggregateCount != 0 {
		t.Fatalf("pending aggregate count=%d err=%v", aggregateCount, err)
	}
	conv := targetHistoryConversation(t, db, "运行", "hfm.com", "u1", "")
	for i := 0; i < 2; i++ {
		if _, err := db.RecordTargetRuns(conv.ID, conv.Title, "", []string{"hfm.com"}, at.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	hits, err = db.CheckTargetRunsForAccess([]string{"hfm.com"}, "u1", RBACScopeOwn)
	if err != nil || len(hits) != 1 || hits[0].RunCount != 1 || hits[0].SubmittedCount != 3 {
		t.Fatalf("actual run count changed by submissions: %+v err=%v", hits, err)
	}
	if err := db.RecomputeTargetRunAggregates(); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteTargetRun("hfm.com"); err != nil {
		t.Fatal(err)
	}
	if hits, err := db.CheckTargetRuns([]string{"hfm.com"}); err != nil || len(hits) != 0 {
		t.Fatalf("delete left submissions: %+v err=%v", hits, err)
	}
}

func TestTaskTargetRegistrationSharesCallerTransaction(t *testing.T) {
	db := newTargetHistoryTestDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := RecordTaskTargetsTx(tx, "q", "t", "rollback.example.com", "", "u1", time.Now()); err != nil || n != 1 {
		t.Fatalf("record tx: n=%d err=%v", n, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if hits, err := db.CheckTargetRuns([]string{"rollback.example.com"}); err != nil || len(hits) != 0 {
		t.Fatalf("caller rollback did not roll back registration: %+v err=%v", hits, err)
	}
	if _, err := RecordTaskTargetsTx(nil, "q", "t", "example.com", "", "", time.Now()); err == nil {
		t.Fatal("nil transaction accepted")
	}
}

func TestTargetBackfillsUseOriginalInputAndRemainIdempotent(t *testing.T) {
	db := newTargetHistoryTestDB(t)
	at := time.Now().UTC()
	targetHistoryQueue(t, db, "q", "u1", at)
	full := strings.Repeat("完整任务描述 ", 100) + " full-message.example.com"
	linked := targetHistoryConversation(t, db, "truncated.example.com", "expanded-user.example.com", "u1", "")
	targetHistoryTask(t, db, "linked", "q", full, linked.ID)
	targetHistoryTask(t, db, "pending", "q", "not-yet-run.example.com", "")
	targetHistoryTask(t, db, "files", "q", "python poc.py results.json 192.0.2.1", "")
	user := targetHistoryConversation(t, db, "renamed.example.com", full+" first-user.example.com", "u1", "")
	// Make ordering explicit: Windows test clocks may give consecutive writes
	// the same timestamp, whose UUID tie-breaker is not an insertion order.
	if _, err := db.Exec(`UPDATE messages SET created_at=? WHERE conversation_id=? AND role='user'`, at.Add(-time.Second), user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(user.ID, "assistant", "assistant-noise.example.com", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(user.ID, "user", "later-user.example.com", nil); err != nil {
		t.Fatal(err)
	}
	targetHistoryConversation(t, db, "filename-title.example.com", "运行 poc.py 输出 results.json", "u1", "")
	targetHistoryConversation(t, db, "legacy-title.example.com", "", "u1", "")
	n, err := db.BackfillTaskTargetRegistrations()
	if err != nil || n != 2 {
		t.Fatalf("task backfill n=%d err=%v", n, err)
	}
	runs, err := db.BackfillTargetRunsFromConversations()
	if err != nil || runs.EventsInserted != 4 || runs.WithTargets != 3 {
		t.Fatalf("conversation backfill %+v err=%v", runs, err)
	}
	hits, err := db.CheckTargetRuns([]string{"full-message.example.com", "not-yet-run.example.com", "first-user.example.com", "legacy-title.example.com"})
	if err != nil || len(hits) != 4 {
		t.Fatalf("missing complete inputs: %+v err=%v", hits, err)
	}
	for _, hit := range hits {
		if hit.Target == "not-yet-run.example.com" && (hit.RunCount != 0 || hit.SubmittedCount != 1) {
			t.Fatalf("pending task counted as run: %+v", hit)
		}
		if hit.Target == "full-message.example.com" && (hit.RunCount != 2 || hit.SubmittedCount != 1) {
			t.Fatalf("complete message not recovered: %+v", hit)
		}
	}
	noise := []string{"template.example.com", "truncated.example.com", "expanded-user.example.com", "renamed.example.com", "assistant-noise.example.com", "later-user.example.com", "filename-title.example.com"}
	if hits, err := db.CheckTargetRuns(noise); err != nil || len(hits) != 0 {
		t.Fatalf("noise entered history: %+v err=%v", hits, err)
	}
	if n, err := db.BackfillTaskTargetRegistrations(); err != nil || n != 0 {
		t.Fatalf("task backfill not idempotent n=%d err=%v", n, err)
	}
	if runs, err := db.BackfillTargetRunsFromConversations(); err != nil || runs.EventsInserted != 0 {
		t.Fatalf("run backfill not idempotent %+v err=%v", runs, err)
	}
}

func TestTargetHistoryForAccessScopesAllMetadataAndDeletion(t *testing.T) {
	db := newTargetHistoryTestDB(t)
	at := time.Now().UTC()
	for _, owner := range []string{"u1", "u2"} {
		for i := 0; i < 2; i++ {
			project, err := db.CreateProject(&Project{Name: fmt.Sprintf("%s-%d", owner, i)})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.SetResourceOwner("project", project.ID, owner); err != nil {
				t.Fatal(err)
			}
			conv := targetHistoryConversation(t, db, owner+" private title", "shared.example.com", owner, project.ID)
			if _, err := db.RecordTargetRuns(conv.ID, conv.Title, project.ID, []string{"shared.example.com"}, at); err != nil {
				t.Fatal(err)
			}
			if _, err := db.RecordTaskTargets(owner, fmt.Sprint(i), owner+" shared.example.com", project.ID, owner, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.RecordTaskTargets("u2", "private", "private.example.com", "", "u2", at); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{RBACScopeOwn, RBACScopeAssigned} {
		hits, err := db.CheckTargetRunsForAccess([]string{"shared.example.com", "private.example.com"}, "u1", scope)
		if err != nil || len(hits) != 1 || hits[0].RunCount != 2 || hits[0].SubmittedCount != 2 || !strings.HasPrefix(hits[0].LastConversationTitle, "u1") || hits[0].LastQueueID != "u1" {
			t.Fatalf("scoped history leaked %+v err=%v", hits, err)
		}
		list, total, err := db.ListTargetRunsForAccess("", 1, 0, "u1", scope)
		if err != nil || total != 1 || len(list) != 1 {
			t.Fatalf("list leaked totals list=%+v total=%d err=%v", list, total, err)
		}
		events, total, err := db.ListTargetRunEventsForAccess("shared.example.com", 10, 0, "u1", scope)
		if err != nil || total != 2 || len(events) != 2 {
			t.Fatalf("events leaked total=%d events=%+v err=%v", total, events, err)
		}
	}
	if hits, err := db.CheckTargetRunsForAccess([]string{"shared.example.com"}, "", RBACScopeOwn); err != nil || len(hits) != 0 {
		t.Fatalf("empty user received global data: %+v err=%v", hits, err)
	}
	if err := db.DeleteTargetRunForAccess("shared.example.com", "u1", RBACScopeOwn); err != nil {
		t.Fatal(err)
	}
	all, err := db.CheckTargetRuns([]string{"shared.example.com"})
	if err != nil || len(all) != 1 || all[0].RunCount != 2 || all[0].SubmittedCount != 2 || all[0].LastQueueID != "u2" {
		t.Fatalf("scoped delete damaged another user: %+v err=%v", all, err)
	}
	var count int
	if err := db.QueryRow("SELECT run_count FROM target_runs WHERE target = ?", "shared.example.com").Scan(&count); err != nil || count != 2 {
		t.Fatalf("aggregate not repaired count=%d err=%v", count, err)
	}
}

func TestTaskTargetBackfillAndCheckAcrossBatchBoundaries(t *testing.T) {
	db := newTargetHistoryTestDB(t)
	targetHistoryQueue(t, db, "bulk", "u1", time.Now())
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	targets := make([]string, 0, targetHistoryBatchSize+12)
	for i := 0; i < targetHistoryBatchSize+12; i++ {
		domain := fmt.Sprintf("bulk-%03d.example.com", i)
		targets = append(targets, domain)
		if _, err := tx.Exec(`INSERT INTO batch_tasks (id, queue_id, message, status) VALUES (?, 'bulk', ?, 'pending')`, fmt.Sprintf("task-%03d", i), domain); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n, err := db.BackfillTaskTargetRegistrations(); err != nil || n != len(targets) {
		t.Fatalf("backfill boundary n=%d err=%v", n, err)
	}
	if hits, err := db.CheckTargetRunsForAccess(targets, "u1", RBACScopeOwn); err != nil || len(hits) != len(targets) {
		t.Fatalf("check boundary len=%d err=%v", len(hits), err)
	}
	if list, total, err := db.ListTargetRunsForAccess("bulk-", 7, 250, "u1", RBACScopeOwn); err != nil || len(list) != 7 || total != len(targets) {
		t.Fatalf("pagination len=%d total=%d err=%v", len(list), total, err)
	}
}
