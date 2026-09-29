package app

import (
	"strings"
	"sync/atomic"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const slowRequestThreshold = time.Second

func isSlowHTTPRequest(duration, firstWrite time.Duration, streaming bool, threshold time.Duration) bool {
	if streaming {
		return firstWrite >= threshold
	}
	return duration >= threshold
}

// timingResponseWriter preserves Gin's streaming/hijacking interfaces. Header
// assignment alone does not count as first byte: the first actual write/flush
// does. Atomic storage accommodates handlers with serialized background writes.
type timingResponseWriter struct {
	gin.ResponseWriter
	firstWrite atomic.Int64
}

func (w *timingResponseWriter) markWrite() {
	w.firstWrite.CompareAndSwap(0, time.Now().UnixNano())
}
func (w *timingResponseWriter) WriteHeaderNow() {
	w.markWrite()
	w.ResponseWriter.WriteHeaderNow()
}
func (w *timingResponseWriter) Write(b []byte) (int, error) {
	w.markWrite()
	return w.ResponseWriter.Write(b)
}
func (w *timingResponseWriter) WriteString(s string) (int, error) {
	w.markWrite()
	return w.ResponseWriter.WriteString(s)
}
func (w *timingResponseWriter) Flush() {
	w.markWrite()
	w.ResponseWriter.Flush()
}

// requestObservationMiddleware measures server-side time, not client/network
// TTFB. Long-lived SSE is logged separately; only a slow first write is a slow
// streaming request. Never record raw URLs, query parameters, bodies or tokens.
func requestObservationMiddleware(log *zap.Logger, db *database.DB, threshold time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		requestID := uuid.NewString()
		c.Header("X-Request-ID", requestID)
		writer := &timingResponseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		defer func() {
			elapsed := time.Since(started)
			firstByte := elapsed
			if first := writer.firstWrite.Load(); first != 0 {
				firstByte = time.Unix(0, first).Sub(started)
			}
			streaming := strings.HasPrefix(writer.Header().Get("Content-Type"), "text/event-stream") || writer.Status() == 101
			slow := isSlowHTTPRequest(elapsed, firstByte, streaming, threshold)
			if log == nil || (!slow && !streaming) {
				return
			}
			route := c.FullPath()
			if route == "" {
				route = "<unmatched>"
			}
			fields := []zap.Field{
				zap.String("request_id", requestID), zap.String("method", c.Request.Method),
				zap.String("route", route), zap.Int("status", writer.Status()),
				zap.Bool("streaming", streaming), zap.Int("response_bytes", max(0, writer.Size())),
				zap.Float64("duration_ms", float64(elapsed)/float64(time.Millisecond)),
				zap.Float64("first_write_ms", float64(firstByte)/float64(time.Millisecond)),
			}
			if db != nil {
				fields = append(fields, zap.Any("database_pool", db.PoolMetrics()))
			}
			if slow {
				log.Warn("HTTP slow request", fields...)
			} else {
				log.Info("HTTP stream completed", fields...)
			}
		}()
		c.Next()
	}
}
