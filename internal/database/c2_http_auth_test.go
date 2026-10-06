package database

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func c2HTTPAuthTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "c2-auth.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, id := range []string{"listener", "other-listener"} {
		if err := db.CreateC2Listener(&C2Listener{ID: id, Name: "test-only", Type: "http_beacon", BindHost: "127.0.0.1", BindPort: 12345}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestC2HTTPIdentityBindingRejectsTakeoverAndStoresOnlyHash(t *testing.T) {
	db := c2HTTPAuthTestDB(t)
	secret := strings.Repeat("test-only-secret-", 3)
	for _, token := range []string{"", "short", strings.Repeat("x", 257)} {
		if ok, err := db.BindC2HTTPIdentity("listener", "invalid", token); err != nil || ok {
			t.Fatal("invalid credential accepted")
		}
	}
	if ok, err := db.BindC2HTTPIdentity("listener", "new-identity", secret); err != nil || !ok {
		t.Fatalf("new identity binding: ok=%v err=%v", ok, err)
	}
	for _, attempt := range []struct{ listener, token string }{
		{"listener", strings.Repeat("other", 12)}, {"other-listener", secret},
	} {
		if ok, err := db.BindC2HTTPIdentity(attempt.listener, "new-identity", attempt.token); err != nil || ok {
			t.Fatal("identity binding overwritten")
		}
		if ok, err := db.VerifyC2HTTPIdentity(attempt.listener, "new-identity", attempt.token); err != nil || ok {
			t.Fatal("foreign credential authenticated")
		}
	}
	var stored string
	if err := db.QueryRow(`SELECT token_hash FROM c2_http_session_auth WHERE implant_uuid=?`, "new-identity").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(secret))
	if stored != hex.EncodeToString(digest[:]) || stored == secret {
		t.Fatal("credential not stored solely as SHA-256")
	}
	if err := db.UpsertC2Session(&C2Session{ID: "session", ListenerID: "listener", ImplantUUID: "new-identity"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.BindC2HTTPIdentity("listener", "new-identity", secret); err != nil || !ok {
		t.Fatal("valid heartbeat binding rejected")
	}
	if err := db.UpsertC2Session(&C2Session{ID: "legacy-session", ListenerID: "listener", ImplantUUID: "legacy-identity"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.BindC2HTTPIdentity("listener", "legacy-identity", secret); err != nil || ok {
		t.Fatal("legacy identity can be claimed by UUID")
	}
	if ok, err := db.VerifyC2HTTPIdentity("listener", "legacy-identity", secret); err != nil || ok {
		t.Fatal("legacy identity bypasses credential check")
	}
	if err := db.DeleteC2Listener("listener"); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.VerifyC2HTTPIdentity("listener", "new-identity", secret); err != nil || ok {
		t.Fatal("deleted listener retained credential binding")
	}
}

func TestC2HTTPIdentityConcurrentFirstBindingCannotOverwrite(t *testing.T) {
	db := c2HTTPAuthTestDB(t)
	secrets := []string{strings.Repeat("a", 43), strings.Repeat("b", 43)}
	var wg sync.WaitGroup
	start := make(chan struct{})
	accepted := make([]bool, len(secrets))
	errs := make([]error, len(secrets))
	for i := range secrets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			accepted[i], errs[i] = db.BindC2HTTPIdentity("listener", "contended-identity", secrets[i])
		}(i)
	}
	close(start)
	wg.Wait()
	count := 0
	for i := range secrets {
		if errs[i] != nil {
			t.Fatalf("concurrent binding failed: %v", errs[i])
		}
		if accepted[i] {
			count++
		}
		ok, err := db.VerifyC2HTTPIdentity("listener", "contended-identity", secrets[i])
		if err != nil || ok != accepted[i] {
			t.Fatal("first credential binding changed after race")
		}
	}
	if count != 1 {
		t.Fatalf("accepted %d independent first credentials", count)
	}
}

func TestC2HTTPAuthMigrationPreservesHistoryAndRejectsLegacyClaims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateC2Listener(&C2Listener{ID: "legacy-listener", ProjectID: "test-only-project", OwnerUserID: "test-only-owner", Name: "historical", Type: "http_beacon", BindHost: "127.0.0.1", BindPort: 12345, ConfigJSON: `{"callback_host":"localhost"}`}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.UpsertC2Session(&C2Session{ID: "legacy-session", ListenerID: "legacy-listener", ImplantUUID: "legacy-uuid", Note: "historical-note"}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.CreateC2Task(&C2Task{ID: "legacy-task", SessionID: "legacy-session", TaskType: "exec", Status: "success", ResultText: "historical-result", CreatedAt: time.Now()}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	// Model the pre-patch schema, then reopen through the normal migration path.
	if _, err := db.Exec(`DROP TABLE c2_http_session_auth`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	listener, err := db.GetC2Listener("legacy-listener")
	if err != nil || listener == nil || listener.ProjectID != "test-only-project" || listener.OwnerUserID != "test-only-owner" || listener.ConfigJSON != `{"callback_host":"localhost"}` {
		t.Fatal("migration changed customized listener fields")
	}
	session, err := db.GetC2Session("legacy-session")
	if err != nil || session == nil || session.Note != "historical-note" {
		t.Fatal("migration changed legacy session")
	}
	task, err := db.GetC2Task("legacy-task")
	if err != nil || task == nil || task.ResultText != "historical-result" || task.Status != "success" {
		t.Fatal("migration changed historical result")
	}
	secret := strings.Repeat("c", 43)
	if ok, err := db.BindC2HTTPIdentity("legacy-listener", "legacy-uuid", secret); err != nil || ok {
		t.Fatal("migration permits legacy identity takeover")
	}
	if ok, err := db.BindC2HTTPIdentity("legacy-listener", "new-uuid", secret); err != nil || !ok {
		t.Fatal("migration prevents a new authenticated identity")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = NewDB(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.VerifyC2HTTPIdentity("legacy-listener", "new-uuid", secret); err != nil || !ok {
		t.Fatal("credential binding lost after reopen")
	}
}

func TestC2HTTPFileIdentitiesUseTopLevelTaskFileIDAndListener(t *testing.T) {
	db := c2HTTPAuthTestDB(t)
	for _, s := range []*C2Session{
		{ID: "session", ListenerID: "listener", ImplantUUID: "identity"},
		{ID: "foreign-session", ListenerID: "other-listener", ImplantUUID: "foreign-identity"},
		{ID: "nested-session", ListenerID: "listener", ImplantUUID: "nested-identity"},
	} {
		if err := db.UpsertC2Session(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, task := range []*C2Task{
		{ID: "owned", SessionID: "session", TaskType: "upload", Payload: map[string]interface{}{"file_id": "owned-file"}},
		{ID: "duplicate", SessionID: "session", TaskType: "upload", Payload: map[string]interface{}{"file_id": "owned-file"}},
		{ID: "foreign", SessionID: "foreign-session", TaskType: "upload", Payload: map[string]interface{}{"file_id": "owned-file"}},
		{ID: "nested", SessionID: "nested-session", TaskType: "upload", Payload: map[string]interface{}{"nested": map[string]interface{}{"file_id": "owned-file"}}},
		{ID: "malformed", SessionID: "nested-session", TaskType: "upload"},
		{ID: "owned-file", SessionID: "nested-session", TaskType: "upload"},
	} {
		if err := db.CreateC2Task(task); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE c2_tasks SET payload_json=? WHERE id=?`, `{"file_id":"owned-file"`, "malformed"); err != nil {
		t.Fatal(err)
	}
	identities, err := db.C2HTTPFileIdentities("listener", "owned-file")
	if err != nil || len(identities) != 1 || identities[0] != "identity" {
		t.Fatal("file ownership not restricted to the top-level file_id and listener")
	}
	identities, err = db.C2HTTPFileIdentities("other-listener", "owned-file")
	if err != nil || len(identities) != 1 || identities[0] != "foreign-identity" {
		t.Fatal("foreign listener identity resolution failed")
	}
	identities, err = db.C2HTTPFileIdentities("listener", "missing-file")
	if err != nil || len(identities) != 0 {
		t.Fatal("unassigned file acquired identities")
	}
}
