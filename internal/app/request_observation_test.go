package app

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSlowRequestSeparatesStreamLifetimeFromFirstWrite(t *testing.T) {
	if isSlowHTTPRequest(time.Hour, time.Millisecond, true, time.Second) {
		t.Fatal("healthy long-lived stream reported as slow")
	}
	if !isSlowHTTPRequest(time.Hour, 2*time.Second, true, time.Second) {
		t.Fatal("slow stream first write not reported")
	}
	if !isSlowHTTPRequest(2*time.Second, time.Millisecond, false, time.Second) {
		t.Fatal("slow ordinary response not reported")
	}
}

func TestRequestObservationPreservesFlushAndDoesNotLogSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zap.DebugLevel)
	router := gin.New()
	router.Use(requestObservationMiddleware(zap.New(core), nil, time.Hour))
	router.GET("/events/:id", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		_, _ = c.Writer.WriteString("data: hello\n\n")
		c.Writer.Flush()
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/events/private-conversation?token=secret-value", nil)
	router.ServeHTTP(w, req)
	if w.Body.String() != "data: hello\n\n" || !w.Flushed || w.Header().Get("X-Request-ID") == "" {
		t.Fatalf("stream behavior changed: %s headers=%v", w.Body.String(), w.Header())
	}
	entries := logs.All()
	if len(entries) != 1 || entries[0].Message != "HTTP stream completed" {
		t.Fatalf("logs=%#v", entries)
	}
	fields := entries[0].ContextMap()
	if fields["route"] != "/events/:id" || fields["streaming"] != true || fields["response_bytes"] != int64(len("data: hello\n\n")) {
		t.Fatalf("metrics=%#v", fields)
	}
	for _, field := range entries[0].Context {
		if strings.Contains(field.String, "secret-value") || strings.Contains(field.String, "private-conversation") {
			t.Fatal("sensitive request data leaked in logs")
		}
	}
}

func TestRequestObservationLogsSlowOrdinaryResponse(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	router := gin.New()
	router.Use(requestObservationMiddleware(zap.New(core), nil, 0))
	router.GET("/slow", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/slow", nil))
	if logs.FilterMessage("HTTP slow request").Len() != 1 {
		t.Fatal("missing slow request metrics")
	}
}
