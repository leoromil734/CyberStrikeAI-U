package handler

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
)

// A dedicated database/sql driver keeps failure and blocked-I/O tests deterministic,
// including on Windows without a working SQLite CGO compiler. It does not replace
// SQLite/PostgreSQL integration tests: it verifies manager transaction boundaries.
type batchManagerTestConnector struct {
	exec      func(string, []driver.NamedValue) error
	query     func(string, []driver.NamedValue) (driver.Rows, error)
	commitErr error
	commits   atomic.Int32
	rollbacks atomic.Int32
}
type batchManagerTestConn struct{ c *batchManagerTestConnector }
type batchManagerTestTx struct{ c *batchManagerTestConnector }
type batchManagerTestDriver struct{}

func (batchManagerTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use connector")
}
func (c *batchManagerTestConnector) Driver() driver.Driver { return batchManagerTestDriver{} }
func (c *batchManagerTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &batchManagerTestConn{c}, nil
}
func (c *batchManagerTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (c *batchManagerTestConn) Close() error              { return nil }
func (c *batchManagerTestConn) Begin() (driver.Tx, error) { return &batchManagerTestTx{c.c}, nil }
func (c *batchManagerTestConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.c.exec != nil {
		if err := c.c.exec(query, args); err != nil {
			return nil, err
		}
	}
	return driver.RowsAffected(1), nil
}
func (c *batchManagerTestConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.c.query != nil {
		return c.c.query(query, args)
	}
	return nil, errors.New("unexpected query: " + query)
}
func (tx *batchManagerTestTx) Commit() error   { tx.c.commits.Add(1); return tx.c.commitErr }
func (tx *batchManagerTestTx) Rollback() error { tx.c.rollbacks.Add(1); return nil }

func batchManagerTestDB(t *testing.T, c *batchManagerTestConnector) *database.DB {
	t.Helper()
	db := sql.OpenDB(c)
	t.Cleanup(func() { _ = db.Close() })
	return &database.DB{DB: db}
}
func batchManagerTestQueue(t *testing.T, m *BatchTaskManager) *BatchTaskQueue {
	t.Helper()
	q, err := m.CreateBatchQueue("original", "role", "eino_single", "manual", "", "", nil, 2, 3, batchTaskInputs("a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func batchManagerAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("operation blocked; possible manager lock held during DB I/O or callback")
	}
}
func batchManagerHasArg(args []driver.NamedValue, want string) bool {
	for _, arg := range args {
		if arg.Value == want {
			return true
		}
	}
	return false
}

func TestBatchManagerCancelCallbacksCanReenter(t *testing.T) {
	for _, operation := range []string{"pause", "cancel", "prepare"} {
		t.Run(operation, func(t *testing.T) {
			m := NewBatchTaskManager(nil)
			q := batchManagerTestQueue(t, m)
			if operation == "prepare" {
				m.UpdateQueueStatus(q.ID, BatchQueueStatusPaused)
				m.UpdateTaskStatus(q.ID, q.Tasks[1].ID, BatchTaskStatusRunning, "", "")
			} else {
				m.UpdateQueueStatus(q.ID, BatchQueueStatusRunning)
			}
			var called atomic.Int32
			m.SetTaskCancel(q.ID, q.Tasks[1].ID, func() {
				m.GetBatchQueue(q.ID)
				m.SetLastRunError(q.ID, "callback")
				m.SetTaskCancel(q.ID, q.Tasks[1].ID, nil)
				called.Add(1)
			})
			done := make(chan struct{})
			var err error
			go func() {
				defer close(done)
				switch operation {
				case "pause":
					if !m.PauseQueue(q.ID) {
						err = errors.New("pause failed")
					}
				case "cancel":
					if !m.CancelQueue(q.ID) {
						err = errors.New("cancel failed")
					}
				case "prepare":
					err = m.PrepareSingleTaskRun(q.ID, q.Tasks[0].ID)
				}
			}()
			batchManagerAwait(t, done)
			if err != nil || called.Load() != 1 {
				t.Fatalf("err=%v callback count=%d", err, called.Load())
			}
		})
	}
}

func TestBatchManagerSingleRunAndCancelBookkeeping(t *testing.T) {
	m := NewBatchTaskManager(nil)
	q := batchManagerTestQueue(t, m)
	m.SetSingleRunTask(q.ID, q.Tasks[1].ID)
	claimed, ok := m.ClaimNextPendingTask(q.ID)
	if !ok || claimed.ID != q.Tasks[1].ID {
		t.Fatal("claim ignored single-run target")
	}
	if _, ok := m.ClaimNextPendingTask(q.ID); ok {
		t.Fatal("claimed sibling during single-run")
	}
	if m.TakeSingleRunTaskIfMatch(q.ID, q.Tasks[0].ID) {
		t.Fatal("mismatched task removed single-run target")
	}
	if !m.TakeSingleRunTaskIfMatch(q.ID, claimed.ID) {
		t.Fatal("matching task did not clear single-run target")
	}
	if next, ok := m.ClaimNextPendingTask(q.ID); !ok || next.ID != q.Tasks[0].ID {
		t.Fatal("could not claim sibling after clearing target")
	}
	m.SetSingleRunTask(q.ID, claimed.ID)
	m.ClearSingleRunTask(q.ID)
	if m.TakeSingleRunTaskIfMatch(q.ID, claimed.ID) {
		t.Fatal("explicit clear retained single-run target")
	}
	var calls atomic.Int32
	m.SetTaskCancel(q.ID, claimed.ID, func() { calls.Add(1) })
	m.SetTaskCancel(q.ID, claimed.ID, nil)
	if !m.CancelQueue(q.ID) || calls.Load() != 0 {
		t.Fatal("removed cancellation callback was invoked")
	}
}

func TestBatchManagerSnapshotIsolation(t *testing.T) {
	m := NewBatchTaskManager(nil)
	next := time.Now()
	q, err := m.CreateBatchQueue("original", "", "eino_single", "cron", "* * * * *", "", &next, 1, 3, batchTaskInputs("a"))
	if err != nil {
		t.Fatal(err)
	}
	id, taskID := q.ID, q.Tasks[0].ID
	wantNext := next
	next = next.Add(time.Hour)
	q.Title, q.Tasks[0].Message = "changed", "changed"
	*q.NextRunAt = next
	m.UpdateQueueStatus(id, BatchQueueStatusRunning)
	m.RecordScheduledRunStart(id)
	m.UpdateTaskStatus(id, taskID, BatchTaskStatusRunning, "", "")
	m.UpdateTaskStatus(id, taskID, BatchTaskStatusCompleted, "result", "")
	m.UpdateQueueStatus(id, BatchQueueStatusCompleted)
	baseline, _ := m.GetBatchQueue(id)
	if baseline.Title != "original" || baseline.Tasks[0].Message != "a" || !baseline.NextRunAt.Equal(wantNext) {
		t.Fatal("create input/output aliases cached queue")
	}
	mutate := func(s *BatchTaskQueue) {
		s.Title = "bad"
		for _, v := range []*time.Time{s.NextRunAt, s.StartedAt, s.CompletedAt, s.LastScheduleTriggerAt, s.Tasks[0].StartedAt, s.Tasks[0].CompletedAt} {
			if v != nil {
				*v = time.Time{}
			}
		}
		s.Tasks[0].Message = "bad"
		s.Tasks[0] = nil
	}
	get, _ := m.GetBatchQueue(id)
	mutate(get)
	mutate(m.GetLoadedQueues()[0])
	mutate(m.GetAllQueues()[0])
	listed, _, err := m.ListQueues(10, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	mutate(listed[0])
	got, _ := m.GetBatchQueue(id)
	if !reflect.DeepEqual(got, baseline) {
		t.Fatal("returned queue snapshot shares mutable fields")
	}
	added, err := m.AddTaskToQueue(id, "new", "")
	if err != nil {
		t.Fatal(err)
	}
	added.Message = "bad"
	m.UpdateQueueStatus(id, BatchQueueStatusPending)
	peek, ok := m.GetNextTask(id)
	if !ok {
		t.Fatal("missing next task")
	}
	peek.Message = "bad"
	claimed, ok := m.ClaimNextPendingTask(id)
	if !ok {
		t.Fatal("missing claim")
	}
	claimed.Message = "bad"
	m.UpdateTaskStatus(id, claimed.ID, BatchTaskStatusCompleted, "", "")
	if claimed.Status != BatchTaskStatusRunning {
		t.Fatal("claim snapshot changed after later update")
	}
	got, _ = m.GetBatchQueue(id)
	if got.Tasks[1].Message != "new" {
		t.Fatal("task return value aliases cached task")
	}
	m.UpdateQueueSchedule(id, "cron", "* * * * *", &next)
	wantNext = next
	next = time.Time{}
	got, _ = m.GetBatchQueue(id)
	if !got.NextRunAt.Equal(wantNext) {
		t.Fatal("schedule input aliases cached time")
	}
}

func TestBatchManagerDifferentQueuesProgressDuringDBWrite(t *testing.T) {
	m := NewBatchTaskManager(nil)
	slow, fast := batchManagerTestQueue(t, m), batchManagerTestQueue(t, m)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	c := &batchManagerTestConnector{exec: func(_ string, args []driver.NamedValue) error {
		if batchManagerHasArg(args, slow.ID) && batchManagerHasArg(args, "slow update") {
			close(entered)
			<-release
		}
		return nil
	}}
	m.SetDB(batchManagerTestDB(t, c))
	writeDone := make(chan struct{})
	go func() { defer close(writeDone); m.SetLastRunError(slow.ID, "slow update") }()
	batchManagerAwait(t, entered)
	fastDone := make(chan struct{})
	go func() {
		defer close(fastDone)
		m.SetLastRunError(fast.ID, "fast update")
		m.GetBatchQueue(fast.ID)
		m.TryMarkQueueExecutor(fast.ID)
		m.UnmarkQueueExecutor(fast.ID)
	}()
	batchManagerAwait(t, fastDone)
	var deleteErr error
	deleteDone := make(chan struct{})
	go func() { defer close(deleteDone); deleteErr = m.DeleteQueue(slow.ID) }()
	select {
	case <-deleteDone:
		t.Fatal("same queue delete passed blocked update")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	batchManagerAwait(t, writeDone)
	batchManagerAwait(t, deleteDone)
	if deleteErr != nil {
		t.Fatal(deleteErr)
	}
	m.mu.RLock()
	_, exists := m.queues[slow.ID]
	lockCount := len(m.queueOps)
	m.mu.RUnlock()
	if exists || lockCount != 0 {
		t.Fatalf("delete or operation lock reclamation failed: exists=%v locks=%d", exists, lockCount)
	}
}

func TestBatchManagerDBFailuresPreserveMemory(t *testing.T) {
	tests := []struct {
		name    string
		running bool
		apply   func(*testing.T, *BatchTaskManager, *BatchTaskQueue)
	}{
		{"task status", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			m.UpdateTaskStatusWithConversationID(q.ID, q.Tasks[0].ID, BatchTaskStatusCompleted, "new", "", "conv")
		}},
		{"queue status", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			m.UpdateQueueStatus(q.ID, BatchQueueStatusRunning)
		}},
		{"schedule", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			now := time.Now()
			m.UpdateQueueSchedule(q.ID, "cron", "* * * * *", &now)
		}},
		{"metadata", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.UpdateQueueMetadata(q.ID, "new", "new", "deep", nil) == nil {
				t.Error("expected error")
			}
		}},
		{"enabled", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.SetScheduleEnabled(q.ID, false) {
				t.Error("expected failure")
			}
		}},
		{"trigger", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) { m.RecordScheduledRunStart(q.ID) }},
		{"schedule error", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) { m.SetLastScheduleError(q.ID, "new") }},
		{"run error", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) { m.SetLastRunError(q.ID, "new") }},
		{"reset", true, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.ResetQueueForRerun(q.ID) {
				t.Error("expected failure")
			}
		}},
		{"message", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.UpdateTaskMessage(q.ID, q.Tasks[0].ID, "new") == nil {
				t.Error("expected error")
			}
		}},
		{"channel", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.UpdateTaskChannel(q.ID, q.Tasks[0].ID, "new") == nil {
				t.Error("expected error")
			}
		}},
		{"retry", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			m.NoteTaskModelRetry(q.ID, q.Tasks[0].ID, 2, "new")
		}},
		{"add", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if _, err := m.AddTaskToQueue(q.ID, "new", ""); err == nil {
				t.Error("expected error")
			}
		}},
		{"prepare", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.PrepareSingleTaskRun(q.ID, q.Tasks[0].ID) == nil {
				t.Error("expected error")
			}
		}},
		{"delete task", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.DeleteTask(q.ID, q.Tasks[0].ID) == nil {
				t.Error("expected error")
			}
		}},
		{"index", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) { m.MoveToNextTask(q.ID) }},
		{"pause", true, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.PauseQueue(q.ID) {
				t.Error("expected failure")
			}
		}},
		{"cancel", true, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.CancelQueue(q.ID) {
				t.Error("expected failure")
			}
		}},
		{"delete queue", false, func(t *testing.T, m *BatchTaskManager, q *BatchTaskQueue) {
			if m.DeleteQueue(q.ID) == nil {
				t.Error("expected error")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewBatchTaskManager(nil)
			q := batchManagerTestQueue(t, m)
			if tt.running {
				m.UpdateQueueStatus(q.ID, BatchQueueStatusRunning)
			}
			m.SetSingleRunTask(q.ID, q.Tasks[0].ID)
			var calls atomic.Int32
			m.SetTaskCancel(q.ID, q.Tasks[0].ID, func() { calls.Add(1) })
			before, _ := m.GetBatchQueue(q.ID)
			var writes atomic.Int32
			c := &batchManagerTestConnector{exec: func(string, []driver.NamedValue) error { writes.Add(1); return errors.New("injected DB failure") }}
			m.SetDB(batchManagerTestDB(t, c))
			tt.apply(t, m, q)
			after, ok := m.GetBatchQueue(q.ID)
			if writes.Load() == 0 {
				t.Fatal("test did not reach database")
			}
			if !ok || !reflect.DeepEqual(before, after) {
				t.Fatalf("DB failure changed memory: before=%+v after=%+v", before, after)
			}
			if calls.Load() != 0 || len(m.taskCancels[q.ID]) != 1 || m.singleRunTasks[q.ID] != q.Tasks[0].ID {
				t.Fatal("DB failure changed execution bookkeeping")
			}
		})
	}
	t.Run("create", func(t *testing.T) {
		m := NewBatchTaskManager(nil)
		m.SetDB(batchManagerTestDB(t, &batchManagerTestConnector{exec: func(string, []driver.NamedValue) error { return errors.New("create failure") }}))
		q, err := m.CreateBatchQueue("test", "", "", "", "", "", nil, 1, 0, nil)
		if err == nil || q != nil || len(m.GetLoadedQueues()) != 0 {
			t.Fatal("failed create published queue")
		}
	})
}

func TestBatchManagerMultiStatementFailureRollsBack(t *testing.T) {
	for _, operation := range []string{"cancel", "prepare"} {
		for _, failCommit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/commit=%v", operation, failCommit), func(t *testing.T) {
				m := NewBatchTaskManager(nil)
				q := batchManagerTestQueue(t, m)
				if operation == "prepare" {
					m.UpdateQueueStatus(q.ID, BatchQueueStatusPaused)
					m.UpdateTaskStatus(q.ID, q.Tasks[0].ID, BatchTaskStatusFailed, "old", "failure")
					m.UpdateTaskStatus(q.ID, q.Tasks[1].ID, BatchTaskStatusRunning, "", "")
				}
				before, _ := m.GetBatchQueue(q.ID)
				var statements, callbacks atomic.Int32
				m.SetTaskCancel(q.ID, q.Tasks[1].ID, func() { callbacks.Add(1) })
				c := &batchManagerTestConnector{exec: func(string, []driver.NamedValue) error {
					if statements.Add(1) == 2 && !failCommit {
						return errors.New("second SQL failed")
					}
					return nil
				}}
				if failCommit {
					c.commitErr = errors.New("commit failed")
				}
				m.SetDB(batchManagerTestDB(t, c))
				if operation == "cancel" {
					if m.CancelQueue(q.ID) {
						t.Fatal("expected cancellation failure")
					}
				} else {
					if m.PrepareSingleTaskRun(q.ID, q.Tasks[0].ID) == nil {
						t.Fatal("expected prepare failure")
					}
				}
				after, _ := m.GetBatchQueue(q.ID)
				if !reflect.DeepEqual(before, after) || callbacks.Load() != 0 {
					t.Fatal("partial failure changed memory/callbacks")
				}
				if !failCommit && (c.commits.Load() != 0 || c.rollbacks.Load() != 1) {
					t.Fatal("partial SQL failure not rolled back")
				}
				if failCommit && c.commits.Load() != 1 {
					t.Fatal("did not test commit failure")
				}
			})
		}
	}
}

type batchManagerTestRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *batchManagerTestRows) Columns() []string { return r.columns }
func (r *batchManagerTestRows) Close() error      { return nil }
func (r *batchManagerTestRows) Next(dst []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dst, r.rows[r.index])
	r.index++
	return nil
}
func batchManagerQueueRows(id string) driver.Rows {
	return &batchManagerTestRows{columns: strings.Split("id,title,role,agent_mode,schedule_mode,cron_expr,next_run_at,schedule_enabled,last_schedule_trigger_at,last_schedule_error,last_run_error,project_id,concurrency,model_retry_max,status,created_at,started_at,completed_at,current_index", ","), rows: [][]driver.Value{{id, "cold", nil, "eino_single", "manual", nil, nil, int64(1), nil, nil, nil, nil, int64(1), int64(3), "pending", "2026-09-29 12:00:00", nil, nil, int64(0)}}}
}

func TestBatchManagerColdListsDoNotHoldGlobalLock(t *testing.T) {
	for _, operation := range []string{"get", "list", "all", "load"} {
		t.Run(operation, func(t *testing.T) {
			m := NewBatchTaskManager(nil)
			fast := batchManagerTestQueue(t, m)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			c := &batchManagerTestConnector{query: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				if strings.Contains(query, "COUNT(") {
					return &batchManagerTestRows{columns: []string{"count"}, rows: [][]driver.Value{{int64(1)}}}, nil
				}
				if strings.Contains(query, "FROM batch_tasks") {
					close(entered)
					<-release
					return &batchManagerTestRows{columns: strings.Split("id,queue_id,message,conversation_id,status,started_at,completed_at,error,result,ai_channel_id,retry_count", ",")}, nil
				}
				return batchManagerQueueRows("cold"), nil
			}}
			m.SetDB(batchManagerTestDB(t, c))
			done := make(chan struct{})
			var err error
			go func() {
				defer close(done)
				switch operation {
				case "get":
					m.GetBatchQueue("cold")
				case "list":
					_, _, err = m.ListQueues(10, 0, "", "")
				case "all":
					m.GetAllQueues()
				case "load":
					err = m.LoadFromDB()
				}
			}()
			batchManagerAwait(t, entered)
			fastDone := make(chan struct{})
			go func() { defer close(fastDone); m.GetBatchQueue(fast.ID); m.SetLastRunError(fast.ID, "progress") }()
			batchManagerAwait(t, fastDone)
			unblock()
			batchManagerAwait(t, done)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBatchManagerSQLiteRollback(t *testing.T) {
	for _, operation := range []string{"cancel", "prepare"} {
		t.Run(operation, func(t *testing.T) {
			m := NewBatchTaskManager(nil)
			q := batchManagerTestQueue(t, m)
			if operation == "prepare" {
				m.UpdateQueueStatus(q.ID, BatchQueueStatusPaused)
				m.UpdateTaskStatus(q.ID, q.Tasks[0].ID, BatchTaskStatusFailed, "old result", "old error")
				m.UpdateTaskStatus(q.ID, q.Tasks[1].ID, BatchTaskStatusRunning, "", "")
			}
			before, _ := m.GetBatchQueue(q.ID)
			sqlDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "batch.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer sqlDB.Close()
			db := &database.DB{DB: sqlDB}
			for _, stmt := range []string{
				"CREATE TABLE batch_task_queues (id TEXT PRIMARY KEY, status TEXT, current_index INTEGER, completed_at DATETIME, last_run_error TEXT)",
				"CREATE TABLE batch_tasks (id TEXT, queue_id TEXT, status TEXT, conversation_id TEXT, started_at DATETIME, completed_at DATETIME, error TEXT, result TEXT, retry_count INTEGER)",
				"CREATE TRIGGER reject_queue_update BEFORE UPDATE ON batch_task_queues BEGIN SELECT RAISE(ABORT, 'injected queue failure'); END",
			} {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec("INSERT INTO batch_task_queues (id, status, current_index) VALUES (?, ?, 0)", q.ID, before.Status); err != nil {
				t.Fatal(err)
			}
			for _, task := range before.Tasks {
				if _, err := db.Exec("INSERT INTO batch_tasks (id, queue_id, status, error, result) VALUES (?, ?, ?, ?, ?)", task.ID, q.ID, task.Status, task.Error, task.Result); err != nil {
					t.Fatal(err)
				}
			}
			m.SetDB(db)
			if operation == "cancel" {
				if m.CancelQueue(q.ID) {
					t.Fatal("expected SQL trigger failure")
				}
			} else if m.PrepareSingleTaskRun(q.ID, q.Tasks[0].ID) == nil {
				t.Fatal("expected SQL trigger failure")
			}
			after, _ := m.GetBatchQueue(q.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed transaction changed memory")
			}
			for _, task := range before.Tasks {
				var status, errorMsg, result string
				if err := db.QueryRow("SELECT status, error, result FROM batch_tasks WHERE id = ?", task.ID).Scan(&status, &errorMsg, &result); err != nil {
					t.Fatal(err)
				}
				if status != task.Status || errorMsg != task.Error || result != task.Result {
					t.Fatal("failed transaction partially persisted task changes")
				}
			}
			if _, err := db.Exec("DROP TRIGGER reject_queue_update"); err != nil {
				t.Fatal(err)
			}
			if operation == "cancel" {
				if !m.CancelQueue(q.ID) {
					t.Fatal("cancel failed after removing trigger")
				}
			} else if err := m.PrepareSingleTaskRun(q.ID, q.Tasks[0].ID); err != nil {
				t.Fatal(err)
			}
			after, _ = m.GetBatchQueue(q.ID)
			var persistedQueueStatus string
			if err := db.QueryRow("SELECT status FROM batch_task_queues WHERE id = ?", q.ID).Scan(&persistedQueueStatus); err != nil {
				t.Fatal(err)
			}
			if persistedQueueStatus != after.Status {
				t.Fatal("successful transaction diverged from cached queue")
			}
			for _, task := range after.Tasks {
				var persistedStatus string
				if err := db.QueryRow("SELECT status FROM batch_tasks WHERE id = ?", task.ID).Scan(&persistedStatus); err != nil {
					t.Fatal(err)
				}
				if persistedStatus != task.Status {
					t.Fatal("successful transaction diverged from cached task")
				}
			}
		})
	}
}

func TestBatchManagerConcurrentClaimsAndSnapshots(t *testing.T) {
	m := NewBatchTaskManager(nil)
	inputs := make([]BatchTaskInput, 80)
	for i := range inputs {
		inputs[i].Message = fmt.Sprint(i)
	}
	q, err := m.CreateBatchQueue("parallel", "", "", "", "", "", nil, 8, 0, inputs)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var seen sync.Map
	var claims atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				task, ok := m.ClaimNextPendingTask(q.ID)
				if !ok {
					return
				}
				if _, duplicate := seen.LoadOrStore(task.ID, true); duplicate {
					t.Error("duplicate claim")
				}
				claims.Add(1)
				snapshot, _ := m.GetBatchQueue(q.ID)
				snapshot.Tasks[0].Message = "caller mutation"
				m.NoteTaskModelRetry(q.ID, task.ID, 1, "retry")
				m.UpdateTaskStatus(q.ID, task.ID, BatchTaskStatusCompleted, "ok", "")
				_ = task.Status
				m.GetLoadedQueues()
			}
		}()
	}
	wg.Wait()
	if claims.Load() != 80 || m.HasPendingOrRunningTasks(q.ID) {
		t.Fatal("unfinished or duplicated tasks")
	}
}
