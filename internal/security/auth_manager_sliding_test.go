package security

import (
	"bytes"
	"testing"
	"time"

	"cyberstrike-ai/internal/cache"
	"cyberstrike-ai/internal/database"
)

// forceSessionState 直接改写内存会话的过期与上次续期时间，用于构造滑动续期场景。
// expiresIn 为负数表示会话已过期；refreshedAgo <= 0 表示从未续期。
func forceSessionState(t *testing.T, manager *AuthManager, token string, expiresIn, refreshedAgo time.Duration) {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	session, ok := manager.sessions[token]
	if !ok {
		t.Fatalf("session %q not found", token)
	}
	session.ExpiresAt = time.Now().Add(expiresIn)
	if refreshedAgo > 0 {
		session.LastRefreshedAt = time.Now().Add(-refreshedAgo)
	} else {
		session.LastRefreshedAt = time.Time{}
	}
	manager.sessions[token] = session
}

func newSlidingTestManager(t *testing.T, hours int) (*AuthManager, *database.DB, cache.Store, string) {
	t.Helper()
	db := seedPersistTestDB(t)
	store := cache.NewMemory()
	manager := newPersistTestManager(t, db, store, hours)
	token, _, err := manager.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return manager, db, store, token
}

// TestSlidingSessionExtendsNearExpiry 验证临近过期的会话在访问时被延长到完整有效期。
func TestSlidingSessionExtendsNearExpiry(t *testing.T) {
	// 4 小时有效期 => 续期窗口 1 小时、最小续期间隔 30 分钟。
	manager, _, _, token := newSlidingTestManager(t, 4)
	// 剩余 30 分钟且已 3 小时未续期：应触发续期。
	forceSessionState(t, manager, token, 30*time.Minute, 3*time.Hour)

	session, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("session should still validate")
	}
	remaining := time.Until(session.ExpiresAt)
	if remaining < 3*time.Hour {
		t.Fatalf("expected expiry to slide to about 4h, got remaining %v", remaining)
	}
	if session.LastRefreshedAt.IsZero() {
		t.Fatal("expected LastRefreshedAt to be stamped on refresh")
	}
}

// TestSlidingSessionNotExtendedFarFromExpiry 验证远离过期的会话不会产生多余的续期写入。
func TestSlidingSessionNotExtendedFarFromExpiry(t *testing.T) {
	manager, _, _, token := newSlidingTestManager(t, 4)

	first, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("session should validate")
	}
	second, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("session should validate again")
	}
	if !first.ExpiresAt.Equal(second.ExpiresAt) {
		t.Fatalf("expiry must not change while far from expiry: %v -> %v", first.ExpiresAt, second.ExpiresAt)
	}
}

// TestSlidingRefreshIsThrottled 验证同一会话在最小间隔内不会被反复续期（避免每个请求都写存储）。
func TestSlidingRefreshIsThrottled(t *testing.T) {
	manager, _, _, token := newSlidingTestManager(t, 4)
	forceSessionState(t, manager, token, 30*time.Minute, 3*time.Hour)

	first, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("session should validate")
	}
	second, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("session should validate again")
	}
	if !first.ExpiresAt.Equal(second.ExpiresAt) {
		t.Fatalf("second validation should be throttled, got %v -> %v", first.ExpiresAt, second.ExpiresAt)
	}
}

// TestExpiredSessionIsNotRevivedBySliding 验证已过期的会话不会被滑动续期救活。
func TestExpiredSessionIsNotRevivedBySliding(t *testing.T) {
	manager, _, _, token := newSlidingTestManager(t, 4)
	forceSessionState(t, manager, token, -time.Minute, 3*time.Hour)

	if _, ok := manager.ValidateToken(token); ok {
		t.Fatal("expired session must not be revived")
	}
}

// TestSlidingRefreshSurvivesRestart 验证续期后的过期时间会持久化，重启后仍然生效。
func TestSlidingRefreshSurvivesRestart(t *testing.T) {
	manager, db, store, token := newSlidingTestManager(t, 4)
	forceSessionState(t, manager, token, 30*time.Minute, 3*time.Hour)

	refreshed, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("session should validate")
	}

	restarted := newPersistTestManager(t, db, store, 4)
	restored, ok := restarted.ValidateToken(token)
	if !ok {
		t.Fatal("refreshed session should survive restart")
	}
	if !restored.ExpiresAt.Equal(refreshed.ExpiresAt) {
		t.Fatalf("restored expiry = %v, want %v", restored.ExpiresAt, refreshed.ExpiresAt)
	}
}

// TestSlidingRefreshWindowAndIntervalScale 验证续期窗口与间隔随有效期缩放且不越界。
func TestSlidingRefreshWindowAndIntervalScale(t *testing.T) {
	longLived := NewAuthManager(168)
	if got := longLived.slidingRefreshWindow(); got != 24*time.Hour {
		t.Fatalf("168h window = %v, want 24h", got)
	}
	if got := longLived.slidingRefreshInterval(); got != time.Hour {
		t.Fatalf("168h interval = %v, want 1h", got)
	}

	shortLived := NewAuthManager(4)
	if got := shortLived.slidingRefreshWindow(); got != time.Hour {
		t.Fatalf("4h window = %v, want 1h", got)
	}
	if got := shortLived.slidingRefreshInterval(); got != 30*time.Minute {
		t.Fatalf("4h interval = %v, want 30m", got)
	}
}

// TestSlidingPersistWritesToStore 验证续期会写回持久化存储。
func TestSlidingPersistWritesToStore(t *testing.T) {
	manager, _, store, token := newSlidingTestManager(t, 4)
	forceSessionState(t, manager, token, 30*time.Minute, 3*time.Hour)

	if _, ok := manager.ValidateToken(token); !ok {
		t.Fatal("session should validate")
	}

	payload, ok := store.Get(t.Context(), sessionPersistKey)
	if !ok {
		t.Fatal("expected refreshed session to be persisted")
	}
	if !bytes.Contains(payload, []byte(token)) {
		t.Fatal("persisted payload should contain the refreshed token")
	}
}
