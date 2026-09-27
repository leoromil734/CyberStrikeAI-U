package security

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cyberstrike-ai/internal/cache"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

// newPersistTestManager 创建一个挂好 RBAC 与持久化存储的认证管理器。
func newPersistTestManager(t *testing.T, db *database.DB, store sessionPersister, hours int) *AuthManager {
	t.Helper()
	manager := NewAuthManager(hours)
	if _, err := manager.AttachRBACStore(db); err != nil {
		t.Fatalf("AttachRBACStore: %v", err)
	}
	if store != nil {
		manager.AttachSessionPersister(store)
	}
	return manager
}

func seedPersistTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "auth-persist.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// 先引导 RBAC 系统角色，否则创建用户会因外键约束失败。
	bootstrapHash, err := HashPassword("bootstrap-admin-secret")
	if err != nil {
		t.Fatalf("HashPassword bootstrap: %v", err)
	}
	if err := db.BootstrapRBAC(bootstrapHash, PermissionCatalog); err != nil {
		t.Fatalf("BootstrapRBAC: %v", err)
	}
	hash, err := HashPassword("operator-secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := db.CreateRBACUser("operator1", "Operator One", hash, true, []string{database.RBACSystemRoleViewer}); err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}
	return db
}

// TestSessionSurvivesRestart 验证进程重启（同一持久化存储、新的 AuthManager）后 token 依然有效。
func TestSessionSurvivesRestart(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()

	before := newPersistTestManager(t, db, store, 168)
	token, expiresAt, err := before.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, ok := before.ValidateToken(token); !ok {
		t.Fatal("token should validate before restart")
	}

	// 模拟重启：新建 AuthManager，复用同一个持久化存储。
	after := newPersistTestManager(t, db, store, 168)
	session, ok := after.ValidateToken(token)
	if !ok {
		t.Fatal("token should still validate after restart")
	}
	if session.Username != "operator1" {
		t.Fatalf("restored username = %q, want operator1", session.Username)
	}
	if !session.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("restored expiry = %v, want %v", session.ExpiresAt, expiresAt)
	}
	if !session.Permissions["chat:read"] {
		t.Fatalf("restored session lost permissions: %#v", session.Permissions)
	}
}

// TestExpiredSessionNotRestored 验证持久化里已过期的会话不会在重启后被恢复。
func TestExpiredSessionNotRestored(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()

	// 直接构造一份已过期的会话表，模拟上次运行遗留的数据。
	stale := `{"stale-token":{"Token":"stale-token","ExpiresAt":"2020-01-01T00:00:00Z","UserID":"u1","Username":"operator1"}}`
	store.Set(context.Background(), sessionPersistKey, []byte(stale), time.Hour)

	after := newPersistTestManager(t, db, store, 168)
	if _, ok := after.ValidateToken("stale-token"); ok {
		t.Fatal("expired session must not be restored after restart")
	}
}

// TestSessionDurationIsAppliedToPersistedTTL 验证持久化 TTL 跟随配置的有效期。
func TestSessionDurationIsAppliedToPersistedTTL(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()

	manager := newPersistTestManager(t, db, store, 168)
	if _, _, err := manager.Authenticate("operator1", "operator-secret"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if manager.SessionDurationHours() != 168 {
		t.Fatalf("SessionDurationHours() = %d, want 168", manager.SessionDurationHours())
	}
	if _, ok := store.Get(context.Background(), sessionPersistKey); !ok {
		t.Fatal("expected session payload written to persister")
	}
}

// TestRevokedSessionStaysRevokedAcrossRestart 验证登出（撤销 token）在重启后依然生效。
func TestRevokedSessionStaysRevokedAcrossRestart(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()

	before := newPersistTestManager(t, db, store, 168)
	token, _, err := before.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	before.RevokeToken(token)

	after := newPersistTestManager(t, db, store, 168)
	if _, ok := after.ValidateToken(token); ok {
		t.Fatal("revoked token must not come back after restart")
	}
}

// TestRevokeAllSessionsClearsPersistedSessions 验证权限变更触发的全量撤销同样会落到持久化存储。
func TestRevokeAllSessionsClearsPersistedSessions(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()

	before := newPersistTestManager(t, db, store, 168)
	token, _, err := before.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	before.RevokeAllSessions()

	after := newPersistTestManager(t, db, store, 168)
	if _, ok := after.ValidateToken(token); ok {
		t.Fatal("RevokeAllSessions must clear persisted sessions")
	}
}

// TestWithoutPersisterKeepsInMemoryOnly 验证未挂载持久化时行为不变（纯内存）。
func TestWithoutPersisterKeepsInMemoryOnly(t *testing.T) {
	db := seedPersistTestDB(t)

	before := newPersistTestManager(t, db, nil, 168)
	token, _, err := before.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	after := newPersistTestManager(t, db, nil, 168)
	if _, ok := after.ValidateToken(token); ok {
		t.Fatal("without persister the session must not survive restart")
	}
}

// TestAttachSessionPersisterIgnoresBrokenPayload 验证存储中脏数据不会阻塞启动。
func TestAttachSessionPersisterIgnoresBrokenPayload(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()
	store.Set(context.Background(), sessionPersistKey, []byte("{not-json"), time.Hour)

	manager := newPersistTestManager(t, db, store, 168)
	if _, ok := manager.ValidateToken("anything"); ok {
		t.Fatal("broken payload must not yield a valid session")
	}
	token, _, err := manager.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate after broken payload: %v", err)
	}
	if _, ok := manager.ValidateToken(token); !ok {
		t.Fatal("manager should keep working after ignoring broken payload")
	}
}
