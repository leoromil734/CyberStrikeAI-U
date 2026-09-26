package app

import (
	"compress/gzip"
	"strings"

	"github.com/gin-gonic/gin"
)

type gzipResponseWriter struct {
	gin.ResponseWriter
	gz *gzip.Writer
}

func (w *gzipResponseWriter) Write(data []byte) (int, error) {
	w.Header().Del("Content-Length")
	return w.gz.Write(data)
}

func (w *gzipResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *gzipResponseWriter) Flush() {
	_ = w.gz.Flush()
	w.ResponseWriter.Flush()
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(code)
}

// responseSpeedMiddleware 压缩 JSON/静态资源，并给静态文件一个短缓存。
// SSE、WebSocket 和显式 stream 路由不压缩，避免把事件流攒在缓冲区里。
func responseSpeedMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/static/") {
			c.Header("Cache-Control", "public, max-age=120")
		}
		if !shouldGzip(c) {
			c.Next()
			return
		}
		gz, err := gzip.NewWriterLevel(c.Writer, gzip.BestSpeed)
		if err != nil {
			c.Next()
			return
		}
		defer gz.Close()
		c.Header("Content-Encoding", "gzip")
		c.Header("Vary", "Accept-Encoding")
		c.Writer = &gzipResponseWriter{ResponseWriter: c.Writer, gz: gz}
		c.Next()
	}
}

func shouldGzip(c *gin.Context) bool {
	if !strings.Contains(c.GetHeader("Accept-Encoding"), "gzip") {
		return false
	}
	if c.GetHeader("Upgrade") != "" {
		return false
	}
	accept := strings.ToLower(c.GetHeader("Accept"))
	if strings.Contains(accept, "text/event-stream") {
		return false
	}
	path := c.Request.URL.Path
	if strings.Contains(path, "/stream") || strings.Contains(path, "task-events") {
		return false
	}
	return true
}
