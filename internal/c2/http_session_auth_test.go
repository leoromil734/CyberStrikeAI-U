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

func TestHTTPSessionIdentityIsolatesCheckInTasksAndResults(t *testing.T) {
	listener := c2SecurityHTTPListener(t)
	db := listener.manager.DB()
	secretA := strings.Repeat("a", 43)
	secretB := strings.Repeat("b", 43)
	checkIn := func(uuid, secret string, encrypted bool) (int, string) {
		raw, err := json.Marshal(ImplantCheckInRequest{ImplantUUID: uuid, Hostname: "test-only-host"})
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		if encrypted {
			body, err = EncryptAESGCM(listener.rec.EncryptionKey, raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(http.MethodPost, "/check_in", strings.NewReader(body))
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleCheckIn(rr, req)
		var response ImplantCheckInResponse
		if rr.Code == http.StatusOK {
			data := rr.Body.Bytes()
			if encrypted {
				data, err = DecryptAESGCM(listener.rec.EncryptionKey, string(data))
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := json.Unmarshal(data, &response); err != nil {
				t.Fatal(err)
			}
		}
		return rr.Code, response.SessionID
	}
	code, sessionA := checkIn("test-only-identity-a", secretA, true)
	if code != http.StatusOK || sessionA == "" {
		t.Fatalf("valid checkin: %d", code)
	}
	code, sessionB := checkIn("test-only-identity-b", secretB, false)
	if code != http.StatusOK || sessionB == "" || sessionB == sessionA {
		t.Fatal("second identity failed")
	}
	if code, id := checkIn("test-only-identity-a", secretA, true); code != http.StatusOK || id != sessionA {
		t.Fatal("valid reconnect failed")
	}
	before, err := db.GetC2Session(sessionA)
	if err != nil {
		t.Fatal(err)
	}
	for _, encrypted := range []bool{false, true} {
		for _, secret := range []string{"", "short", strings.Repeat("x", 257), secretB} {
			if code, _ := checkIn("test-only-identity-a", secret, encrypted); code != http.StatusNotFound {
				t.Fatal("foreign identity takeover accepted")
			}
		}
	}
	after, err := db.GetC2Session(sessionA)
	if err != nil || after == nil || before == nil || !after.LastCheckIn.Equal(before.LastCheckIn) {
		t.Fatal("unauthorized heartbeat mutated session")
	}
	// Missing explicit UUID does not merge different credentials behind the same IP.
	_, generatedA := checkIn("", secretA, false)
	_, generatedB := checkIn("", secretB, false)
	if generatedA == "" || generatedB == "" || generatedA == generatedB {
		t.Fatal("same-IP identities merged")
	}
	if code, id := checkIn("", secretA, false); code != http.StatusOK || id != generatedA {
		t.Fatal("derived identity reconnect failed")
	}

	task := &database.C2Task{ID: "test-only-owned-task", SessionID: sessionA, TaskType: "exec", Status: "queued", CreatedAt: time.Now()}
	if err := db.CreateC2Task(task); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"", secretB, secretA} {
		req := httptest.NewRequest(http.MethodGet, "/tasks?session_id="+sessionA, nil)
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleTasks(rr, req)
		saved, err := db.GetC2Task(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		if secret != secretA {
			if rr.Code != http.StatusNotFound || saved.Status != "queued" {
				t.Fatal("foreign poll dispatched task")
			}
		} else if rr.Code != http.StatusOK || saved.Status != "sent" {
			t.Fatal("valid task poll failed")
		}
	}

	fileID := "test-only-downstream-file"
	if err := db.CreateC2Task(&database.C2Task{ID: "test-only-file-task", SessionID: sessionA, TaskType: "upload", Payload: map[string]interface{}{"file_id": fileID}, Status: "sent", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(listener.manager.StorageDir(), "downstream")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileID+".bin"), []byte("test-only-downstream-content"), 0600); err != nil {
		t.Fatal(err)
	}
	uploadBody, err := EncryptAESGCM(listener.rec.EncryptionKey, []byte("test-only-upload-content"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"", secretB, secretA} {
		req := httptest.NewRequest(http.MethodGet, "/file/"+fileID, nil)
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleFileServe(rr, req)
		expected := http.StatusNotFound
		if secret == secretA {
			expected = http.StatusOK
		}
		if rr.Code != expected {
			t.Fatalf("file read identity status %d expected %d", rr.Code, expected)
		}
		if secret == secretA {
			plain, err := DecryptAESGCM(listener.rec.EncryptionKey, rr.Body.String())
			if err != nil {
				t.Fatal(err)
			}
			var file struct {
				FileData string `json:"file_data"`
			}
			if err := json.Unmarshal(plain, &file); err != nil {
				t.Fatal(err)
			}
			decoded, err := base64.StdEncoding.DecodeString(file.FileData)
			if err != nil || string(decoded) != "test-only-downstream-content" {
				t.Fatal("valid file download failed")
			}
		}
		req = httptest.NewRequest(http.MethodPost, "/upload?task_id="+task.ID, strings.NewReader(uploadBody))
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr = httptest.NewRecorder()
		listener.handleUpload(rr, req)
		if rr.Code != expected {
			t.Fatalf("file write identity status %d expected %d", rr.Code, expected)
		}
		_, path, err := uploadPathForTask(listener.manager.StorageDir(), task.ID)
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := os.ReadFile(path)
		if secret != secretA {
			if !os.IsNotExist(readErr) {
				t.Fatal("foreign file write mutated storage")
			}
		} else if readErr != nil || string(content) != "test-only-upload-content" {
			t.Fatal("valid file upload failed")
		}
	}
	raw, err := json.Marshal(TaskResultReport{TaskID: task.ID, Success: true, Output: "test-only-result"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncryptAESGCM(listener.rec.EncryptionKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"", secretB, secretA} {
		req := httptest.NewRequest(http.MethodPost, "/result", strings.NewReader(body))
		req.Header.Set("X-Implant-Token", listener.rec.ImplantToken)
		req.Header.Set("X-Session-Token", secret)
		rr := httptest.NewRecorder()
		listener.handleResult(rr, req)
		saved, err := db.GetC2Task(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		if secret != secretA {
			if rr.Code != http.StatusNotFound || saved.Status != "sent" || saved.ResultText != "" {
				t.Fatal("foreign result persisted")
			}
		} else if rr.Code != http.StatusOK || saved.Status != "success" || saved.ResultText != "test-only-result" {
			t.Fatal("valid result rejected")
		}
	}
}
