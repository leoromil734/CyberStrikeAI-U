package c2

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
)

// Uses only net.Pipe and a temporary database; never opens a listening socket.
func TestTCPBeaconFileOwnershipInMemory(t *testing.T) {
	for _, tc := range []struct {
		name, op, resource, sessionChange string
		beforeCheckIn, allowed            bool
	}{
		{name: "upload-before-checkin", op: "upload", resource: "t_owned", beforeCheckIn: true},
		{name: "upload-foreign-session", op: "upload", resource: "t_other"},
		{name: "upload-foreign-listener", op: "upload", resource: "t_foreign"},
		{name: "upload-missing-task", op: "upload", resource: "t_missing"},
		{name: "upload-owned-traversal-task", op: "upload", resource: "../outside"},
		{name: "upload-owned-ads-task", op: "upload", resource: "task:stream"},
		{name: "upload-deleted-session", op: "upload", resource: "t_owned", sessionChange: "delete"},
		{name: "upload-moved-session", op: "upload", resource: "t_owned", sessionChange: "move"},
		{name: "upload-owned", op: "upload", resource: "t_owned", allowed: true},
		{name: "file-before-checkin", op: "file", resource: "f_owned", beforeCheckIn: true},
		{name: "file-foreign-session", op: "file", resource: "f_other"},
		{name: "file-foreign-listener", op: "file", resource: "f_foreign"},
		{name: "file-unbound", op: "file", resource: "f_unbound"},
		{name: "file-task-id-is-not-authorization", op: "file", resource: "t_owned"},
		{name: "file-nested-id", op: "file", resource: "f_nested"},
		{name: "file-malformed-payload", op: "file", resource: "f_bad"},
		{name: "file-deleted-session", op: "file", resource: "f_owned", sessionChange: "delete"},
		{name: "file-moved-session", op: "file", resource: "f_owned", sessionChange: "move"},
		{name: "file-owned", op: "file", resource: "f_owned", allowed: true},
		{name: "file-shared-explicit-grant", op: "file", resource: "f_shared", allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := c2SecurityHTTPListener(t)
			db := h.manager.DB()
			foreign := *h.rec
			foreign.ID, foreign.Name = "foreign-listener", "foreign-test-only"
			if err := db.CreateC2Listener(&foreign); err != nil {
				t.Fatal(err)
			}
			for _, sess := range []*database.C2Session{
				{ID: "other", ListenerID: "listener", ImplantUUID: "other-uuid", Status: "active"},
				{ID: "foreign", ListenerID: foreign.ID, ImplantUUID: "foreign-uuid", Status: "active"},
			} {
				if err := db.UpsertC2Session(sess); err != nil {
					t.Fatal(err)
				}
			}
			tasks := []*database.C2Task{
				{ID: "t_owned", SessionID: "session", Payload: map[string]interface{}{"file_id": "f_owned"}},
				{ID: "t_other", SessionID: "other", Payload: map[string]interface{}{"file_id": "f_other"}},
				{ID: "t_foreign", SessionID: "foreign", Payload: map[string]interface{}{"file_id": "f_foreign"}},
				{ID: "t_shared_owned", SessionID: "session", Payload: map[string]interface{}{"file_id": "f_shared"}},
				{ID: "t_shared_other", SessionID: "other", Payload: map[string]interface{}{"file_id": "f_shared"}},
				{ID: "t_nested", SessionID: "session", Payload: map[string]interface{}{"nested": map[string]string{"file_id": "f_nested"}}},
				{ID: "t_bad", SessionID: "session"},
				{ID: "../outside", SessionID: "session"},
				{ID: "task:stream", SessionID: "session"},
			}
			for _, task := range tasks {
				task.TaskType, task.Status = "upload", "sent"
				if err := db.CreateC2Task(task); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`UPDATE c2_tasks SET payload_json=? WHERE id=?`, `{"file_id":"f_bad",`, "t_bad"); err != nil {
				t.Fatal(err)
			}
			store := h.manager.StorageDir()
			for _, dir := range []string{"uploads", "downstream"} {
				if err := os.MkdirAll(filepath.Join(store, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range []string{"t_owned", "t_other", "t_foreign"} {
				if err := os.WriteFile(filepath.Join(store, "uploads", id+".bin"), []byte("original"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range []string{"f_owned", "f_other", "f_foreign", "f_shared", "f_unbound", "t_owned", "f_nested", "f_bad"} {
				if err := os.WriteFile(filepath.Join(store, "downstream", id+".bin"), []byte("test-only-downstream"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			listener := &TCPReverseListener{rec: h.rec, cfg: h.cfg, manager: h.manager, logger: h.logger}
			server, client := net.Pipe()
			done := make(chan struct{})
			go func() { defer close(done); listener.handleTCPBeaconSession(server, bufio.NewReader(server)) }()
			t.Cleanup(func() {
				_ = client.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("in-memory listener did not stop")
				}
			})
			reader := bufio.NewReader(client)
			exchange := func(env map[string]interface{}) ([]byte, error) {
				t.Helper()
				env["token"] = listener.rec.ImplantToken
				raw, err := json.Marshal(env)
				if err != nil {
					t.Fatal(err)
				}
				body, err := EncryptAESGCM(listener.rec.EncryptionKey, raw)
				if err != nil {
					t.Fatal(err)
				}
				_ = client.SetDeadline(time.Now().Add(3 * time.Second))
				if err := writeTCPBeaconFrame(nil, client, body); err != nil {
					return nil, err
				}
				response, err := readTCPBeaconFrame(reader)
				if err != nil {
					return nil, err
				}
				return DecryptAESGCM(listener.rec.EncryptionKey, response)
			}
			if !tc.beforeCheckIn {
				raw, err := exchange(map[string]interface{}{"op": "check_in", "check": ImplantCheckInRequest{ImplantUUID: "test-uuid"}})
				if err != nil {
					t.Fatal(err)
				}
				var check ImplantCheckInResponse
				if err := json.Unmarshal(raw, &check); err != nil || check.SessionID != "session" {
					t.Fatalf("unexpected check-in response: %s (%v)", raw, err)
				}
			}
			switch tc.sessionChange {
			case "delete":
				if _, err := db.Exec(`DELETE FROM c2_sessions WHERE id=?`, "session"); err != nil {
					t.Fatal(err)
				}
			case "move":
				if _, err := db.Exec(`UPDATE c2_sessions SET listener_id=? WHERE id=?`, foreign.ID, "session"); err != nil {
					t.Fatal(err)
				}
			}
			env := map[string]interface{}{"op": tc.op}
			if tc.op == "upload" {
				env["upload"] = map[string]string{"task_id": tc.resource, "data_b64": base64.StdEncoding.EncodeToString([]byte("test-only-upload"))}
			} else {
				env["file"] = map[string]string{"file_id": tc.resource}
			}
			raw, err := exchange(env)
			if tc.allowed {
				if err != nil {
					t.Fatalf("authorized request rejected: %v", err)
				}
				if tc.op == "file" {
					var result map[string]string
					if err := json.Unmarshal(raw, &result); err != nil || result["file_data"] != base64.StdEncoding.EncodeToString([]byte("test-only-downstream")) {
						t.Fatalf("unexpected file response: %s (%v)", raw, err)
					}
				}
			} else if !errors.Is(err, io.EOF) {
				t.Fatalf("unauthorized request must close connection without a response, got %s (%v)", raw, err)
			}
			for _, id := range []string{"t_owned", "t_other", "t_foreign"} {
				want := "original"
				if tc.allowed && tc.op == "upload" && id == "t_owned" {
					want = "test-only-upload"
				}
				data, err := os.ReadFile(filepath.Join(store, "uploads", id+".bin"))
				if err != nil || string(data) != want {
					t.Fatalf("unexpected upload contents for %s: %q (%v)", id, data, err)
				}
			}
			entries, err := os.ReadDir(filepath.Join(store, "uploads"))
			if err != nil || len(entries) != 3 {
				t.Fatalf("unauthorized upload created a file: %v", err)
			}
			if _, err := os.Stat(filepath.Join(store, "outside.bin")); !os.IsNotExist(err) {
				t.Fatal("upload escaped storage")
			}
			if tc.sessionChange != "delete" {
				for _, task := range tasks {
					got, err := db.GetC2Task(task.ID)
					if err != nil || got == nil || got.Status != "sent" || got.ResultText != "" {
						t.Fatalf("file operation changed task %s: %v", task.ID, err)
					}
				}
			}
		})
	}
}

func TestTCPBeaconSecurityBoundariesInMemory(t *testing.T) {
	for _, scenario := range []string{"tasks-before-checkin", "result-before-checkin", "foreign-session-tasks", "foreign-session-result", "valid-result", "traversal-upload"} {
		t.Run(scenario, func(t *testing.T) {
			httpListener := c2SecurityHTTPListener(t)
			db := httpListener.manager.DB()
			if err := db.UpsertC2Session(&database.C2Session{ID: "other", ListenerID: "listener", ImplantUUID: "other-uuid", Status: "active"}); err != nil {
				t.Fatal(err)
			}
			for _, task := range []*database.C2Task{
				{ID: "t_owned", SessionID: "session", TaskType: "exec", Status: "sent"},
				{ID: "t_other", SessionID: "other", TaskType: "exec", Status: "queued"},
			} {
				if err := db.CreateC2Task(task); err != nil {
					t.Fatal(err)
				}
			}
			listener := &TCPReverseListener{rec: httpListener.rec, cfg: httpListener.cfg, manager: httpListener.manager, logger: httpListener.logger}
			server, client := net.Pipe()
			done := make(chan struct{})
			go func() { defer close(done); listener.handleTCPBeaconSession(server, bufio.NewReader(server)) }()
			t.Cleanup(func() {
				_ = client.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("in-memory listener did not stop")
				}
			})
			reader := bufio.NewReader(client)
			exchange := func(env map[string]interface{}) ([]byte, error) {
				t.Helper()
				env["token"] = listener.rec.ImplantToken
				raw, err := json.Marshal(env)
				if err != nil {
					t.Fatal(err)
				}
				body, err := EncryptAESGCM(listener.rec.EncryptionKey, raw)
				if err != nil {
					t.Fatal(err)
				}
				_ = client.SetDeadline(time.Now().Add(3 * time.Second))
				if err := writeTCPBeaconFrame(nil, client, body); err != nil {
					return nil, err
				}
				response, err := readTCPBeaconFrame(reader)
				if err != nil {
					return nil, err
				}
				return DecryptAESGCM(listener.rec.EncryptionKey, response)
			}
			if scenario != "tasks-before-checkin" && scenario != "result-before-checkin" {
				if _, err := exchange(map[string]interface{}{"op": "check_in", "check": ImplantCheckInRequest{ImplantUUID: "test-uuid", Hostname: "test-only-host"}}); err != nil {
					t.Fatal(err)
				}
			}
			var env map[string]interface{}
			switch scenario {
			case "tasks-before-checkin":
				env = map[string]interface{}{"op": "tasks", "session_id": "session"}
			case "foreign-session-tasks":
				env = map[string]interface{}{"op": "tasks", "session_id": "other"}
			case "result-before-checkin", "valid-result":
				env = map[string]interface{}{"op": "result", "result": TaskResultReport{TaskID: "t_owned", Success: true, Output: "test-only-result"}}
			case "foreign-session-result":
				env = map[string]interface{}{"op": "result", "result": TaskResultReport{TaskID: "t_other", Success: true, Output: "test-only-result"}}
			case "traversal-upload":
				env = map[string]interface{}{"op": "upload", "upload": map[string]string{"task_id": "../outside", "data_b64": base64.StdEncoding.EncodeToString([]byte("test-only-file"))}}
			}
			_, err := exchange(env)
			if scenario == "valid-result" {
				if err != nil {
					t.Fatal("valid result was rejected")
				}
			} else if err == nil {
				t.Fatal("invalid in-memory request was accepted")
			}
			other, err := db.GetC2Task("t_other")
			if err != nil || other == nil || other.Status != "queued" || other.ResultText != "" {
				t.Fatal("foreign task mutated")
			}
			owned, err := db.GetC2Task("t_owned")
			expected := "sent"
			if scenario == "valid-result" {
				expected = "success"
			}
			if err != nil || owned == nil || owned.Status != expected {
				t.Fatal("bound task has unexpected state")
			}
			if _, err := os.Stat(filepath.Join(listener.manager.StorageDir(), "outside.bin")); !os.IsNotExist(err) {
				t.Fatal("upload escaped storage")
			}
		})
	}
}
