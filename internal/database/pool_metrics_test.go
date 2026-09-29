package database

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestPoolMetricsAndIntervalWaitObservation(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	db := &DB{logger: zap.New(core), dialect: DialectPostgres}
	before := sql.DBStats{WaitCount: 2, WaitDuration: time.Second}
	after := sql.DBStats{MaxOpenConnections: 40, OpenConnections: 40, InUse: 39, Idle: 1, WaitCount: 5, WaitDuration: 1500 * time.Millisecond}
	db.logPoolObservation("conversations", before, after)
	entries := logs.FilterMessage("Database connection pool wait detected").All()
	if len(entries) != 1 {
		t.Fatal("missing pool wait warning")
	}
	fields := entries[0].ContextMap()
	if fields["wait_count_delta"] != int64(3) || fields["wait_duration_ms_delta"] != float64(500) {
		t.Fatalf("delta=%#v", fields)
	}
	metrics := poolMetricsFromStats(after)
	if metrics.WaitDurationMS != 1500 || metrics.MaxOpenConnections != 40 || metrics.WaitCount != 5 {
		t.Fatalf("metrics=%#v", metrics)
	}
	db.logPoolObservation("conversations", after, after)
	if logs.FilterMessage("Database connection pool wait detected").Len() != 1 {
		t.Fatal("old waits incorrectly logged as new waits")
	}
}

func TestPoolObserverStopsWithDatabase(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "pool.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if db.poolObserverDone == nil {
		t.Fatal("observer was not started")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-db.poolObserverDone:
	default:
		t.Fatal("pool observer leaked after close")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
