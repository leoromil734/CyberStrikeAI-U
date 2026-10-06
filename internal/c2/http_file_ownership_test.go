package c2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
)

func TestHTTPUploadEnforcesListenerOwnership(t *testing.T) {
	listener := c2SecurityHTTPListener(t)
	task := &database.C2Task{ID: "test-only-file-task", SessionID: "session", TaskType: "download", Status: "sent", CreatedAt: time.Now()}
	if err := listener.manager.DB().CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	body, err := EncryptAESGCM(listener.rec.EncryptionKey, []byte("test-only-upload"))
	if err != nil {
		t.Fatal(err)
	}
	dir, path, err := uploadPathForTask(listener.manager.StorageDir(), task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, owned := range []bool{false, true} {
		listener.rec.ID = "foreign-listener"
		if owned {
			listener.rec.ID = "listener"
		}
		upload := httptest.NewRequest(http.MethodPost, "/upload?task_id="+task.ID, strings.NewReader(body))
		upload.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		upload.Header.Set("X-Session-Token", testHTTPSessionToken)
		rr := httptest.NewRecorder()
		listener.handleUpload(rr, upload)
		expected := http.StatusNotFound
		if owned {
			expected = http.StatusOK
		}
		if rr.Code != expected {
			t.Fatalf("upload owned=%v: status=%d", owned, rr.Code)
		}
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		expectedContent := "original"
		if owned {
			expectedContent = "test-only-upload"
		}
		if string(saved) != expectedContent {
			t.Fatalf("unexpected file mutation owned=%v", owned)
		}
	}
}

func TestHTTPBeaconListener_HandleUploadConfinesTaskID(t *testing.T) {
	l := c2SecurityHTTPListener(t)
	body, err := EncryptAESGCM(l.rec.EncryptionKey, []byte("safe upload"))
	if err != nil {
		t.Fatal(err)
	}
	for _, taskID := range []string{"t_safe123", "../owned", `..\owned`, "sub/owned", "task:stream"} {
		// Even malformed historical task IDs with valid ownership must not escape storage.
		if err := l.manager.DB().CreateC2Task(&database.C2Task{ID: taskID, SessionID: "session", TaskType: "download", Status: "sent", CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/upload?task_id="+url.QueryEscape(taskID), strings.NewReader(body))
		req.Header.Set("X-Implant-Token", l.rec.ImplantToken)
		req.Header.Set("X-Session-Token", testHTTPSessionToken)
		rr := httptest.NewRecorder()
		l.handleUpload(rr, req)
		expected := http.StatusNotFound
		if taskID == "t_safe123" {
			expected = http.StatusOK
		}
		if rr.Code != expected {
			t.Fatalf("task ID %q: status=%d", taskID, rr.Code)
		}
	}
	got, err := os.ReadFile(filepath.Join(l.manager.StorageDir(), "uploads", "t_safe123.bin"))
	if err != nil || string(got) != "safe upload" {
		t.Fatal("valid upload not saved")
	}
	if _, err := os.Stat(filepath.Join(l.manager.StorageDir(), "owned.bin")); !os.IsNotExist(err) {
		t.Fatal("outside file created")
	}
}

func TestHTTPBeaconListener_HandleResultRejectsPlaintextJSON(t *testing.T) {
	l := c2SecurityHTTPListener(t)
	if err := l.manager.DB().CreateC2Task(&database.C2Task{ID: "t_test", SessionID: "session", TaskType: "exec", Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"task_id":"t_test","success":true}`, "corrupt-ciphertext"} {
		req := httptest.NewRequest(http.MethodPost, "/result", strings.NewReader(body))
		req.Header.Set("X-Implant-Token", l.rec.ImplantToken)
		req.Header.Set("X-Session-Token", testHTTPSessionToken)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		l.handleResult(rr, req)
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "404 Not Found") {
			t.Fatal("result accepted without authenticated ciphertext")
		}
		saved, err := l.manager.DB().GetC2Task("t_test")
		if err != nil || saved == nil || saved.Status != "sent" {
			t.Fatal("invalid result mutated task")
		}
	}
}

func TestHTTPFileServeRequiresTaskFileIDBinding(t *testing.T) {
	l := c2SecurityHTTPListener(t)
	db := l.manager.DB()
	// The file exists, but sharing its ID with a task ID is not an ownership grant.
	fileID := "test-only-unassigned-file"
	if err := db.CreateC2Task(&database.C2Task{ID: fileID, SessionID: "session", TaskType: "upload", Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(l.manager.StorageDir(), "downstream")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileID+".bin"), []byte("unassigned"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, listenerID := range []string{"listener", "foreign-listener"} {
		l.rec.ID = listenerID
		req := httptest.NewRequest(http.MethodGet, "/file/"+fileID, nil)
		req.Header.Set("X-Implant-Token", l.rec.ImplantToken)
		req.Header.Set("X-Session-Token", testHTTPSessionToken)
		rr := httptest.NewRecorder()
		l.handleFileServe(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatal("unassigned downstream file accepted")
		}
	}
	if err := db.CreateC2Task(&database.C2Task{ID: "t_file_owner", SessionID: "session", TaskType: "upload", Payload: map[string]interface{}{"file_id": fileID}, Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	for _, listenerID := range []string{"foreign-listener", "listener"} {
		l.rec.ID = listenerID
		req := httptest.NewRequest(http.MethodGet, "/file/"+fileID, nil)
		req.Header.Set("X-Implant-Token", l.rec.ImplantToken)
		req.Header.Set("X-Session-Token", testHTTPSessionToken)
		rr := httptest.NewRecorder()
		l.handleFileServe(rr, req)
		expected := http.StatusNotFound
		if listenerID == "listener" {
			expected = http.StatusOK
		}
		if rr.Code != expected {
			t.Fatal("downstream task binding did not enforce listener ownership")
		}
	}
}
