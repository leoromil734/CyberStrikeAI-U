package database

import (
	"strings"
	"testing"
)

func TestAdaptPostgresPlaceholders(t *testing.T) {
	d := DialectPostgres
	got := d.Adapt(`SELECT id FROM t WHERE a = ? AND b = ?`)
	want := `SELECT id FROM t WHERE a = $1 AND b = $2`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAdaptInsertOrIgnore(t *testing.T) {
	d := DialectPostgres
	got := d.Adapt(`INSERT OR IGNORE INTO rbac_permissions (key, description) VALUES (?, ?)`)
	if !strings.Contains(got, "INSERT INTO") {
		t.Fatalf("expected INSERT INTO: %s", got)
	}
	if !strings.Contains(strings.ToUpper(got), "ON CONFLICT DO NOTHING") {
		t.Fatalf("expected ON CONFLICT DO NOTHING: %s", got)
	}
	if strings.Contains(strings.ToUpper(got), "OR IGNORE") {
		t.Fatalf("OR IGNORE should be removed: %s", got)
	}
	if !strings.Contains(got, "$1") || !strings.Contains(got, "$2") {
		t.Fatalf("expected $n placeholders: %s", got)
	}
}

func TestAdaptPragmaTableInfoLiteral(t *testing.T) {
	d := DialectPostgres
	got := d.Adapt(`SELECT COUNT(*) FROM pragma_table_info('conversations') WHERE name='pinned'`)
	if strings.Contains(strings.ToLower(got), "pragma") {
		t.Fatalf("pragma should be rewritten: %s", got)
	}
	if !strings.Contains(got, "information_schema.columns") {
		t.Fatalf("expected information_schema: %s", got)
	}
	if !strings.Contains(got, "conversations") || !strings.Contains(got, "pinned") {
		t.Fatalf("expected table/column names preserved: %s", got)
	}
}

func TestAdaptDatetimeNow(t *testing.T) {
	d := DialectPostgres
	got := d.Adapt(`INSERT INTO t (created_at) VALUES (datetime('now'))`)
	if strings.Contains(strings.ToLower(got), "datetime(") {
		t.Fatalf("datetime('now') should be rewritten: %s", got)
	}
	if !strings.Contains(strings.ToUpper(got), "NOW()") {
		t.Fatalf("expected NOW(): %s", got)
	}
}

func TestDurationMsSQL(t *testing.T) {
	pg := DialectPostgres.durationMsSQL("?", "start_time")
	if strings.Contains(strings.ToLower(pg), "julianday") {
		t.Fatalf("postgres duration must not use julianday: %s", pg)
	}
	if !strings.Contains(strings.ToUpper(pg), "EXTRACT") {
		t.Fatalf("expected EXTRACT for postgres: %s", pg)
	}
	// Adapt rewrites ? → $n for the full query path
	full := DialectPostgres.Adapt(`UPDATE t SET duration_ms = ` + pg + ` WHERE status = ?`)
	if strings.Contains(full, "?") {
		t.Fatalf("expected rebound placeholders: %s", full)
	}

	sq := DialectSQLite.durationMsSQL("?", "start_time")
	if !strings.Contains(strings.ToLower(sq), "julianday") {
		t.Fatalf("sqlite duration should use julianday: %s", sq)
	}
}

func TestAdaptJuliandayFallback(t *testing.T) {
	// Legacy SQLite-only duration expression should be rewritten for PG
	raw := `UPDATE t SET duration_ms = MAX(0, CAST((julianday(?) - julianday(start_time)) * 86400000 AS INTEGER)) WHERE status = 'running'`
	got := DialectPostgres.Adapt(raw)
	if strings.Contains(strings.ToLower(got), "julianday") {
		t.Fatalf("julianday should be rewritten: %s", got)
	}
	if strings.Contains(strings.ToUpper(got), "MAX(0") {
		t.Fatalf("MAX(0,...) clamp should become GREATEST: %s", got)
	}
	if !strings.Contains(strings.ToUpper(got), "GREATEST") {
		t.Fatalf("expected GREATEST: %s", got)
	}
	if !strings.Contains(strings.ToUpper(got), "EXTRACT") {
		t.Fatalf("expected EXTRACT: %s", got)
	}
}

func TestAdaptSQLiteUnchanged(t *testing.T) {
	q := `INSERT OR IGNORE INTO t (a) VALUES (?)`
	if DialectSQLite.Adapt(q) != q {
		t.Fatal("sqlite adapt should be identity")
	}
}

func TestBuildPostgresDSN(t *testing.T) {
	dsn, err := BuildPostgresDSN("", "127.0.0.1", 5432, "u", "p", "cyberstrike", "disable")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "postgres://") || !strings.Contains(dsn, "cyberstrike") {
		t.Fatalf("unexpected dsn: %s", dsn)
	}
}
