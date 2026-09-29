package database

import (
	"database/sql"
	"time"

	"go.uber.org/zap"
)

const poolObservationInterval = 30 * time.Second

// PoolMetrics describes this database/sql pool only (not all PostgreSQL server
// connections). Wait counters are cumulative since this process opened the pool.
type PoolMetrics struct {
	MaxOpenConnections int     `json:"maxOpenConnections"`
	OpenConnections    int     `json:"openConnections"`
	InUse              int     `json:"inUse"`
	Idle               int     `json:"idle"`
	WaitCount          int64   `json:"waitCount"`
	WaitDurationMS     float64 `json:"waitDurationMs"`
	MaxIdleClosed      int64   `json:"maxIdleClosed"`
	MaxIdleTimeClosed  int64   `json:"maxIdleTimeClosed"`
	MaxLifetimeClosed  int64   `json:"maxLifetimeClosed"`
}

func (db *DB) PoolMetrics() PoolMetrics {
	if db == nil || db.DB == nil {
		return PoolMetrics{}
	}
	return poolMetricsFromStats(db.Stats())
}

func poolMetricsFromStats(s sql.DBStats) PoolMetrics {
	return PoolMetrics{
		MaxOpenConnections: s.MaxOpenConnections, OpenConnections: s.OpenConnections,
		InUse: s.InUse, Idle: s.Idle, WaitCount: s.WaitCount,
		WaitDurationMS: float64(s.WaitDuration) / float64(time.Millisecond),
		MaxIdleClosed:  s.MaxIdleClosed, MaxIdleTimeClosed: s.MaxIdleTimeClosed,
		MaxLifetimeClosed: s.MaxLifetimeClosed,
	}
}

// Each successfully opened pool owns its observer, including a separately
// configured/reconfigured knowledge database. Close stops and joins the loop.
func (db *DB) startPoolObserver(name string) {
	if db == nil || db.DB == nil || db.logger == nil {
		return
	}
	db.poolObserverStop = make(chan struct{})
	db.poolObserverDone = make(chan struct{})
	previous := db.Stats()
	go func() {
		defer close(db.poolObserverDone)
		ticker := time.NewTicker(poolObservationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-db.poolObserverStop:
				return
			case <-ticker.C:
				current := db.Stats()
				db.logPoolObservation(name, previous, current)
				previous = current
			}
		}
	}()
}

func (db *DB) logPoolObservation(name string, previous, current sql.DBStats) {
	fields := []zap.Field{
		zap.String("pool", name), zap.String("driver", string(db.Dialect())),
		zap.Duration("sample_interval", poolObservationInterval),
		zap.Any("stats", poolMetricsFromStats(current)),
		zap.Int64("wait_count_delta", max(0, current.WaitCount-previous.WaitCount)),
		zap.Float64("wait_duration_ms_delta", float64(max(0, current.WaitDuration-previous.WaitDuration))/float64(time.Millisecond)),
	}
	if current.WaitCount > previous.WaitCount || current.WaitDuration > previous.WaitDuration {
		db.logger.Warn("Database connection pool wait detected", fields...)
	} else {
		db.logger.Debug("Database connection pool sample", fields...)
	}
}
