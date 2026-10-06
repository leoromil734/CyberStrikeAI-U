package c2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
)

func TestResultTransportOwnershipRejectsForeignTask(t *testing.T) {
	m, db := c2SecurityTestManager(t)
	if err := db.UpsertC2Session(&database.C2Session{ID: "other", ListenerID: "listener", ImplantUUID: "other-uuid", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	task := &database.C2Task{ID: "t_owner", SessionID: "session", TaskType: "exec", Status: "sent", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	report := TaskResultReport{TaskID: task.ID, Success: true, Output: "test-only-result", BlobBase64: base64.StdEncoding.EncodeToString([]byte("test-only-blob")), BlobSuffix: ".txt"}
	for _, source := range [][2]string{{"listener", "other"}, {"foreign-listener", "session"}, {"foreign-listener", ""}, {"", "session"}} {
		if err := m.IngestTaskResultFromListener(source[0], source[1], report); err != ErrAuthFailed {
			t.Fatalf("source %v: %v", source, err)
		}
		saved, err := db.GetC2Task(task.ID)
		if err != nil || saved == nil || saved.Status != "sent" || saved.ResultText != "" || saved.ResultBlobPath != "" {
			t.Fatal("foreign result persisted")
		}
		if _, err := os.Stat(filepath.Join(m.StorageDir(), "results", task.ID+".txt")); !os.IsNotExist(err) {
			t.Fatal("foreign result wrote a blob")
		}
	}
	if err := m.IngestTaskResultFromListener("listener", "session", report); err != nil {
		t.Fatal(err)
	}
	saved, err := db.GetC2Task(task.ID)
	if err != nil || saved == nil || saved.Status != "success" || saved.ResultText != report.Output || saved.ResultBlobPath == "" {
		t.Fatal("valid result failed")
	}
}

func TestHTTPResultCannotUpdateAnotherListenerTask(t *testing.T) {
	l := c2SecurityHTTPListener(t)
	db := l.manager.DB()
	task := &database.C2Task{ID: "t_foreign", SessionID: "session", TaskType: "exec", Status: "sent", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	l.rec.ID = "http_other"
	raw, err := json.Marshal(TaskResultReport{TaskID: task.ID, Success: true, Output: "forged"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncryptAESGCM(l.rec.EncryptionKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/result", strings.NewReader(body))
	req.Header.Set("X-Implant-Token", l.rec.ImplantToken)
	req.Header.Set("X-Session-Token", testHTTPSessionToken)
	rr := httptest.NewRecorder()
	l.handleResult(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatal("accepted foreign listener result")
	}
	saved, err := db.GetC2Task(task.ID)
	if err != nil || saved == nil || saved.Status != "sent" || saved.ResultText != "" {
		t.Fatal("foreign result persisted")
	}
	req = httptest.NewRequest(http.MethodGet, "/tasks?session_id=session", nil)
	req.Header.Set("X-Implant-Token", l.rec.ImplantToken)
	req.Header.Set("X-Session-Token", testHTTPSessionToken)
	rr = httptest.NewRecorder()
	l.handleTasks(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("foreign session task request status: %d", rr.Code)
	}
}

func TestCheckInCannotMoveAnExistingSessionToAnotherListener(t *testing.T) {
	m, db := c2SecurityTestManager(t)
	if _, err := m.IngestCheckIn("foreign-listener", ImplantCheckInRequest{ImplantUUID: "test-uuid", Hostname: "forged"}); err != ErrAuthFailed {
		t.Fatalf("expected rejection, got %v", err)
	}
	saved, err := db.GetC2Session("session")
	if err != nil || saved == nil || saved.ListenerID != "listener" || saved.Hostname == "forged" {
		t.Fatal("session changed")
	}
}
