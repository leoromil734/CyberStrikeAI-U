package c2

import (
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

const testHTTPSessionToken = "test-only-session-credential-0123456789abcdef"

// These fixtures never start a listener or run generated client code.
func c2SecurityTestManager(t *testing.T) (*Manager, *database.DB) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "security.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateC2Listener(&database.C2Listener{
		ID: "listener", Name: "test-only", Type: string(ListenerTypeHTTPBeacon),
		BindHost: "127.0.0.1", BindPort: 12345, EncryptionKey: key,
		ImplantToken: "test-only-listener-token", Status: "stopped", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	bindHTTPIdentityFixture(t, db, "listener", "test-uuid", testHTTPSessionToken)
	if err := db.UpsertC2Session(&database.C2Session{
		ID: "session", ListenerID: "listener", ImplantUUID: "test-uuid", Hostname: "test-only-host",
		Status: "active", FirstSeenAt: time.Now(), LastCheckIn: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return NewManager(db, zap.NewNop(), t.TempDir()), db
}

func c2SecurityHTTPListener(t *testing.T) *HTTPBeaconListener {
	t.Helper()
	m, db := c2SecurityTestManager(t)
	rec, err := db.GetC2Listener("listener")
	if err != nil || rec == nil {
		t.Fatalf("load fixture listener: %v", err)
	}
	return &HTTPBeaconListener{
		rec: rec, manager: m, logger: zap.NewNop(),
		cfg: &ListenerConfig{DefaultSleep: 5, BeaconFilePath: "/file/"},
	}
}

func bindHTTPIdentityFixture(t *testing.T, db *database.DB, listener, uuid, secret string) {
	t.Helper()
	if ok, err := db.BindC2HTTPIdentity(listener, uuid, secret); err != nil || !ok {
		t.Fatalf("bind test identity: ok=%v err=%v", ok, err)
	}
}
