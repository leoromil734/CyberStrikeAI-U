package handler

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestProcessDetailsLatestPageSkipsHistorySummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "latest.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("latest page", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 105; i++ {
		if err := db.AddProcessDetail(msg.ID, conv.ID, "tool_call", fmt.Sprint(i), map[string]interface{}{"toolCallId": fmt.Sprint(i), "toolName": "test"}); err != nil {
			t.Fatal(err)
		}
	}
	h := NewConversationHandler(db, zap.NewNop())
	request := func(query string) map[string]interface{} {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/api/messages/"+msg.ID+"/process-details?"+query, nil)
		c.Params = gin.Params{{Key: "id", Value: msg.ID}}
		h.GetMessageProcessDetails(c)
		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	latest := request("latest=1&limit=50&include_summary=false")
	if latest["offset"] != float64(55) || latest["nextOffset"] != float64(105) || latest["total"] != float64(105) || latest["hasMore"] != false {
		t.Fatalf("wrong pagination: %#v", latest)
	}
	if _, exists := latest["toolExecutions"]; exists {
		t.Fatal("full-history summary returned on opt-out path")
	}
	if got := len(latest["processDetails"].([]interface{})); got != 50 {
		t.Fatalf("details=%d", got)
	}
	legacy := request("limit=2")
	if len(legacy["toolExecutions"].([]interface{})) != 105 {
		t.Fatal("legacy summary contract changed")
	}
	first := request("offset=0&limit=50&include_summary=0")
	if first["offset"] != float64(0) || first["nextOffset"] != float64(50) || first["hasMore"] != true {
		t.Fatalf("first page: %#v", first)
	}
}

func TestProcessDetailsPageCursorUsesRawRows(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "duplicates.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("duplicates", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := db.AddMessage(conv.ID, "assistant", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := db.AddProcessDetail(msg.ID, conv.ID, "thinking", "same", map[string]interface{}{"streamId": "same"}); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/?limit=4&include_summary=false", nil)
	c.Params = gin.Params{{Key: "id", Value: msg.ID}}
	NewConversationHandler(db, zap.NewNop()).GetMessageProcessDetails(c)
	var body struct {
		NextOffset int           `json:"nextOffset"`
		HasMore    bool          `json:"hasMore"`
		Details    []interface{} `json:"processDetails"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.NextOffset != 4 || body.HasMore {
		t.Fatalf("cursor=%d hasMore=%v", body.NextOffset, body.HasMore)
	}
	if len(body.Details) >= 4 {
		t.Fatal("fixture did not exercise deduplication")
	}
}
