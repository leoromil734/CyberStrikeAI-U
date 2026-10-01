package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

func TestToolExecutionText(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"valid", "中文与emoji🙂\n\r\t\\x00�", "中文与emoji🙂\n\r\t\\x00�"},
		{"nul", "before\x00after", `before\x00after`},
		{"observed bytes", "\xfc\x93\x8b", `\xfc\x93\x8b`},
		{"mixed", "中文\x00\xfc�🙂", `中文\x00\xfc�🙂`},
		{"incomplete rune", "中\xe6\x96", `中\xe6\x96`},
		{"invalid sequences", "\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80", `\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := toolExecutionText(tc.raw)
			if got != tc.want {
				t.Fatalf("text = %q, want %q", got, tc.want)
			}
			if !utf8.ValidString(got) || strings.IndexByte(got, 0) >= 0 {
				t.Fatalf("unsafe database text: %q", got)
			}
			if again := toolExecutionText(got); again != got {
				t.Fatalf("encoding is not idempotent: %q -> %q", got, again)
			}
		})
	}

	// Every standalone byte is either valid ASCII or an explicit byte escape.
	for b := 0; b <= 255; b++ {
		raw := string([]byte{byte(b)})
		want := raw
		if b == 0 || b >= 128 {
			want = fmt.Sprintf(`\x%02x`, b)
		}
		if got := toolExecutionText(raw); got != want {
			t.Fatalf("byte %02x: got %q, want %q", b, got, want)
		}
	}
}

func TestSaveToolExecutionPostgresSafeTextParameters(t *testing.T) {
	for _, raw := range []string{"合法中文🙂�\n\\x00", "httpx: \xfc", "exec: \x00\x93\x00\x8b", "katana: \xfc", "中\xe6\x96"} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			db, capture := newPGTextCaptureDB(t)
			now := time.Now()
			exec := &mcp.ToolExecution{
				ID: "execution", ToolName: "exec", Status: mcp.ToolExecutionStatusFailed,
				Arguments: map[string]interface{}{"command": "测试"},
				Error:     raw, PartialOutput: raw, PartialOutputBytes: int64(len(raw)),
				PartialOutputTruncated: true, PartialOutputUpdatedAt: &now,
				StartTime: now.Add(-time.Second), EndTime: &now, Duration: time.Second,
				Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: raw}}, IsError: true},
			}
			if err := db.SaveToolExecution(exec); err != nil {
				t.Fatalf("SaveToolExecution: %v", err)
			}
			writes := capture.snapshot()
			if len(writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(writes))
			}
			write := writes[0]
			if !strings.Contains(write.query, "ON CONFLICT (id) DO UPDATE SET") || !strings.Contains(write.query, "$16") || strings.Contains(write.query, "?") {
				t.Fatalf("not PostgreSQL-adapted SQL: %s", write.query)
			}
			want := toolExecutionText(raw)
			if write.args[5].Value != want || write.args[9].Value != want {
				t.Fatalf("error/partial parameters = %q/%q, want %q", write.args[5].Value, write.args[9].Value, want)
			}
			if write.args[3].Value != mcp.ToolExecutionStatusFailed || write.args[7].Value != now || write.args[10].Value != int64(len(raw)) || write.args[11].Value != int64(1) || write.args[12].Value != now {
				t.Fatalf("terminal state or raw output metadata changed: %#v", write.args)
			}
			var stored mcp.ToolResult
			if err := json.Unmarshal([]byte(write.args[4].Value.(string)), &stored); err != nil {
				t.Fatal(err)
			}
			if stored.Content[0].Text != want || !stored.IsError {
				t.Fatalf("stored result = %#v", stored)
			}
			if exec.Error != raw || exec.PartialOutput != raw || exec.Result.Content[0].Text != raw || exec.PartialOutputBytes != int64(len(raw)) {
				t.Fatalf("persistence mutated raw execution: %#v", exec)
			}
		})
	}
}

func TestToolExecutionPostgresTextUpdates(t *testing.T) {
	db, capture := newPGTextCaptureDB(t)
	raw := "中文\x00\xfc"
	result := &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: raw}}, IsError: true}
	if err := db.UpdateToolExecutionResult("execution", result); err != nil {
		t.Fatal(err)
	}
	write := capture.snapshot()[0]
	var got mcp.ToolResult
	if err := json.Unmarshal([]byte(write.args[0].Value.(string)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Content[0].Text != `中文\x00\xfc` || result.Content[0].Text != raw {
		t.Fatalf("updated result = %#v, original = %#v", got, result)
	}

	now := time.Now()
	if _, err := db.CancelOrphanedRunningToolExecutions(now, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := db.FinalizeStaleRunningToolExecutions(now, time.Minute, nil, raw); err != nil {
		t.Fatal(err)
	}
	writes := capture.snapshot()
	if len(writes) != 3 {
		t.Fatalf("writes = %d, want result update plus two error updates", len(writes))
	}
	for _, write := range writes[1:] {
		if write.args[0].Value != `中文\x00\xfc` {
			t.Fatalf("unsafe orphan message parameter: %#v", write.args[0])
		}
	}
}

func TestToolExecutionPostgresEmptyAndJSONShape(t *testing.T) {
	db, capture := newPGTextCaptureDB(t)
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "empty", StartTime: time.Now(), Status: mcp.ToolExecutionStatusRunning}); err != nil {
		t.Fatal(err)
	}
	write := capture.snapshot()[0]
	if write.args[4].Value != nil || write.args[5].Value != nil || write.args[9].Value != nil {
		t.Fatalf("empty result/error/partial must remain NULL: %#v", write.args)
	}
	for _, result := range []*mcp.ToolResult{{Content: nil}, {Content: []mcp.Content{}}, {Content: []mcp.Content{{Type: "text", Text: "中文🙂�"}}}} {
		got, err := marshalToolExecutionResult(result)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(result)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("legal JSON changed: got %s, want %s", got, want)
		}
	}
}

func TestToolExecutionPostgresDriverRejectsRawBytesAndReturnsSaveErrors(t *testing.T) {
	db, capture := newPGTextCaptureDB(t)
	for _, raw := range []string{"\x00", "\xfc", "\xe6\x96"} {
		if _, err := db.DB.ExecContext(context.Background(), "raw text validation", raw); err == nil {
			t.Fatalf("driver accepted invalid PostgreSQL text %q", raw)
		}
	}
	failure := errors.New("database unavailable")
	capture.execErr = failure
	if err := db.SaveToolExecution(&mcp.ToolExecution{ID: "failed-save", Status: mcp.ToolExecutionStatusFailed, Error: "\xfc"}); !errors.Is(err, failure) {
		t.Fatalf("SaveToolExecution error = %v, want original driver error", err)
	}
	if len(capture.snapshot()) != 0 {
		t.Fatal("failed save must not be reported as a successful write")
	}
}

func TestToolExecutionServiceSplitUTF8PostgresPersistence(t *testing.T) {
	for _, status := range []string{mcp.ToolExecutionStatusCompleted, mcp.ToolExecutionStatusFailed, mcp.ToolExecutionStatusCancelled} {
		t.Run(status, func(t *testing.T) {
			db, capture := newPGTextCaptureDB(t)
			service := mcp.NewExecutionService(db, zap.NewNop())
			started := make(chan struct{})
			finish := make(chan struct{})
			ended := make(chan *mcp.ToolExecution, 1)
			raw := "中文🙂\x00\xfc"
			handle, err := service.Submit(context.Background(), mcp.ExecutionRequest{
				ToolName: "exec",
				Run: func(ctx context.Context) (*mcp.ToolResult, error) {
					close(started)
					select {
					case <-finish:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					if status == mcp.ToolExecutionStatusFailed {
						return nil, errors.New(raw)
					}
					return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: raw}}}, nil
				},
				OnDone: func(exec *mcp.ToolExecution) { ended <- exec },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { service.Cancel(handle.ID, "") })
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not start")
			}

			// Persist every byte prefix, including chunks splitting Chinese and
			// four-byte emoji. Subsequent chunks must use the original raw buffer.
			for i := range len(raw) {
				if !service.AppendPartialOutput(handle.ID, raw[i:i+1]) {
					t.Fatal("AppendPartialOutput failed")
				}
				snap, err := service.Get(handle.ID)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.SaveToolExecution(snap.Execution); err != nil {
					t.Fatalf("saving byte prefix %d: %v", i+1, err)
				}
				if snap.Execution.PartialOutput != raw[:i+1] || snap.Execution.PartialOutputBytes != int64(i+1) {
					t.Fatalf("raw prefix changed after persistence: %#v", snap.Execution)
				}
				live, _ := service.Get(handle.ID)
				if live.Execution.PartialOutput != raw[:i+1] {
					t.Fatalf("persistence contaminated running buffer: %q", live.Execution.PartialOutput)
				}
				writes := capture.snapshot()
				if got := writes[len(writes)-1].args[9].Value; got != toolExecutionText(raw[:i+1]) {
					t.Fatalf("persisted prefix %d = %q", i+1, got)
				}
			}

			if status == mcp.ToolExecutionStatusCancelled {
				if !service.Cancel(handle.ID, "") {
					t.Fatal("Cancel failed")
				}
			} else {
				close(finish)
			}
			var final *mcp.ToolExecution
			select {
			case final = <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not finish")
			}
			writes := capture.snapshot()
			write := writes[len(writes)-1]
			if final.Status != status || final.EndTime == nil || write.args[3].Value != status || write.args[7].Value == nil {
				t.Fatalf("real terminal state was not saved: %#v / %#v", final, write.args)
			}
			if final.PartialOutput != raw || final.PartialOutputBytes != int64(len(raw)) || final.PartialOutputTruncated {
				t.Fatalf("raw final output metadata changed: %#v", final)
			}
			if got := write.args[9].Value; got != `中文🙂\x00\xfc` || write.args[10].Value != int64(len(raw)) {
				t.Fatalf("split UTF-8 did not recover at terminal save: %#v", write.args)
			}
			if status == mcp.ToolExecutionStatusFailed && (final.Error != raw || write.args[5].Value != `中文🙂\x00\xfc`) {
				t.Fatalf("terminal error lost original bytes: %#v / %#v", final, write.args[5])
			}
		})
	}
}

func TestToolExecutionTextSQLiteTerminalSurvivesReconcile(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "monitor.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw := "中文\x00\xfc\x93\x8b"
	now := time.Now()
	exec := &mcp.ToolExecution{
		ID: "binary-output", ToolName: "exec", Status: mcp.ToolExecutionStatusRunning,
		StartTime: now.Add(-time.Hour),
	}
	if err := db.SaveToolExecution(exec); err != nil {
		t.Fatal(err)
	}
	exec.Status = mcp.ToolExecutionStatusFailed
	exec.Error = raw
	exec.PartialOutput = raw
	exec.PartialOutputBytes = int64(len(raw))
	exec.PartialOutputUpdatedAt = &now
	exec.EndTime = &now
	exec.Duration = now.Sub(exec.StartTime)
	exec.Result = &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: raw}}, IsError: true}
	if err := db.SaveToolExecution(exec); err != nil {
		t.Fatal(err)
	}
	// A saved real terminal state must not subsequently be treated as an orphan.
	if n, err := db.FinalizeStaleRunningToolExecutions(now.Add(time.Minute), 0, nil, "执行已中断（会话已结束）"); err != nil || n != 0 {
		t.Fatalf("reconcile changed saved terminal record: n=%d, err=%v", n, err)
	}
	stored, err := db.GetToolExecution(exec.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := `中文\x00\xfc\x93\x8b`
	if stored.Status != mcp.ToolExecutionStatusFailed || stored.EndTime == nil || stored.Error != want || stored.PartialOutput != want || stored.Result.Content[0].Text != want {
		t.Fatalf("terminal round-trip lost output/state: %#v", stored)
	}
	if stored.PartialOutputBytes != int64(len(raw)) || stored.PartialOutputTruncated || exec.Error != raw || exec.PartialOutput != raw {
		t.Fatalf("raw output or byte metadata changed: original=%#v, stored=%#v", exec, stored)
	}
}

// pgTextCapture validates actual database/sql driver parameters using the
// PostgreSQL dialect. It deliberately rejects NUL/invalid UTF-8 like a UTF-8
// PostgreSQL text column. This is a fake driver, not a PostgreSQL integration.
type pgTextCapture struct {
	mu      sync.Mutex
	writes  []pgTextWrite
	execErr error
}

type pgTextWrite struct {
	query string
	args  []driver.NamedValue
}

func (c *pgTextCapture) snapshot() []pgTextWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]pgTextWrite(nil), c.writes...)
}

func newPGTextCaptureDB(t *testing.T) (*DB, *pgTextCapture) {
	t.Helper()
	capture := &pgTextCapture{}
	sqlDB := sql.OpenDB(pgTextConnector{capture})
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &DB{DB: sqlDB, dialect: DialectPostgres, logger: zap.NewNop()}, capture
}

type pgTextConnector struct{ capture *pgTextCapture }

func (c pgTextConnector) Connect(context.Context) (driver.Conn, error) {
	return pgTextConn{c.capture}, nil
}
func (c pgTextConnector) Driver() driver.Driver { return pgTextDriver{c.capture} }

type pgTextDriver struct{ capture *pgTextCapture }

func (d pgTextDriver) Open(string) (driver.Conn, error) { return pgTextConn{d.capture}, nil }

type pgTextConn struct{ capture *pgTextCapture }

func (c pgTextConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (c pgTextConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected Begin") }
func (c pgTextConn) Close() error              { return nil }
func (c pgTextConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	for _, arg := range args {
		if text, ok := arg.Value.(string); ok && (!utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0) {
			return nil, fmt.Errorf("SQLSTATE 22021: invalid text in parameter %d", arg.Ordinal)
		}
	}
	c.capture.mu.Lock()
	defer c.capture.mu.Unlock()
	if c.capture.execErr != nil {
		return nil, c.capture.execErr
	}
	c.capture.writes = append(c.capture.writes, pgTextWrite{query, append([]driver.NamedValue(nil), args...)})
	return driver.RowsAffected(1), nil
}
func (c pgTextConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "SELECT id, start_time FROM tool_executions") {
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
	return &pgTextStaleRows{}, nil
}

type pgTextStaleRows struct{ read bool }

func (r *pgTextStaleRows) Columns() []string { return []string{"id", "start_time"} }
func (r *pgTextStaleRows) Close() error      { return nil }
func (r *pgTextStaleRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	dest[0], dest[1] = "stale-execution", time.Now().Add(-time.Hour)
	return nil
}
