package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/google/uuid"
)

// sessionPersistKey 是会话表在持久化存储（Redis）中的键名。
const sessionPersistKey = "auth:sessions"

// Predefined errors for authentication operations.
var (
	ErrInvalidPassword = errors.New("invalid password")
)

// Session represents an authenticated user session.
type Session struct {
	Token            string
	ExpiresAt        time.Time
	LastRefreshedAt  time.Time
	UserID           string
	Username         string
	DisplayName      string
	Roles            []string
	Permissions      map[string]bool
	PermissionScopes map[string]string
	Scope            string
}

// sessionPersister 是会话持久化的窄接口，由 cache.Store 实现。
// 用于让登录状态在进程重启后依然保留。
type sessionPersister interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration)
	Delete(ctx context.Context, key string)
}

// AuthManager manages password-based authentication and session lifecycle.
type AuthManager struct {
	sessionDuration time.Duration
	db              *database.DB
	persister       sessionPersister

	mu       sync.RWMutex
	sessions map[string]Session
}

// NewAuthManager creates a new AuthManager instance.
func NewAuthManager(sessionDurationHours int) *AuthManager {
	if sessionDurationHours <= 0 {
		sessionDurationHours = 12
	}

	return &AuthManager{
		sessionDuration: time.Duration(sessionDurationHours) * time.Hour,
		sessions:        make(map[string]Session),
	}
}

// AttachSessionPersister 挂载会话持久化存储（通常是 Redis），
// 使服务重启后已登录用户无需重新输入密码。
// store 为 nil 时保持纯内存会话；读取失败时静默忽略，不影响启动。
func (a *AuthManager) AttachSessionPersister(store sessionPersister) {
	if store == nil {
		return
	}

	a.mu.Lock()
	a.persister = store
	a.mu.Unlock()

	raw, ok := store.Get(context.Background(), sessionPersistKey)
	if !ok || len(raw) == 0 {
		return
	}
	stored := make(map[string]Session)
	if err := json.Unmarshal(raw, &stored); err != nil {
		return
	}

	now := time.Now()
	a.mu.Lock()
	for token, session := range stored {
		if strings.TrimSpace(token) == "" || now.After(session.ExpiresAt) {
			continue
		}
		a.sessions[token] = session
	}
	a.mu.Unlock()
}

// persist 把当前会话表写回持久化存储，并在存储上刷新 TTL。
// 必须在未持有 a.mu 时调用。
func (a *AuthManager) persist() {
	a.mu.RLock()
	persister := a.persister
	duration := a.sessionDuration
	snapshot := make(map[string]Session, len(a.sessions))
	for token, session := range a.sessions {
		snapshot[token] = session
	}
	a.mu.RUnlock()

	if persister == nil {
		return
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return
	}
	persister.Set(context.Background(), sessionPersistKey, raw, duration)
}

// AttachRBACStore enables multi-user RBAC authentication. When no users exist yet,
// it bootstraps the built-in admin account and returns the generated initial password.
func (a *AuthManager) AttachRBACStore(db *database.DB) (generatedAdminPassword string, err error) {
	if db == nil {
		return "", errors.New("database is required for authentication")
	}

	needsAdminPassword, err := db.RBACNeedsAdminPassword()
	if err != nil {
		return "", err
	}

	adminPasswordHash := ""
	if needsAdminPassword {
		generatedAdminPassword, err = GenerateStrongPassword(24)
		if err != nil {
			return "", err
		}
		adminPasswordHash, err = HashPassword(generatedAdminPassword)
		if err != nil {
			return "", err
		}
	}

	if err := db.BootstrapRBAC(adminPasswordHash, PermissionCatalog); err != nil {
		return "", err
	}

	a.mu.Lock()
	a.db = db
	a.mu.Unlock()
	return generatedAdminPassword, nil
}

// Authenticate validates the password and creates a new session.
func (a *AuthManager) Authenticate(username, password string) (string, time.Time, error) {
	session, err := a.authenticateSession(username, password)
	if err != nil {
		return "", time.Time{}, err
	}
	a.mu.Lock()
	a.sessions[session.Token] = session
	a.mu.Unlock()
	a.persist()
	return session.Token, session.ExpiresAt, nil
}

func (a *AuthManager) authenticateSession(username, password string) (Session, error) {
	token := uuid.NewString()
	expiresAt := time.Now().Add(a.sessionDuration)

	a.mu.RLock()
	db := a.db
	a.mu.RUnlock()
	if db == nil {
		return Session{}, errors.New("authentication store is not configured")
	}

	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		username = "admin"
	}
	user, err := db.GetRBACUserByUsername(username)
	if err != nil {
		if err == sql.ErrNoRows {
			return Session{}, ErrInvalidPassword
		}
		return Session{}, err
	}
	if !user.Enabled || !VerifyPasswordHash(password, user.PasswordHash) {
		return Session{}, ErrInvalidPassword
	}
	access, err := db.ResolveRBACAccess(user.ID)
	if err != nil {
		return Session{}, err
	}
	roleIDs := make([]string, 0, len(access.Roles))
	for _, role := range access.Roles {
		roleIDs = append(roleIDs, role.ID)
	}
	return Session{
		Token:            token,
		ExpiresAt:        expiresAt,
		LastRefreshedAt:  time.Now(),
		UserID:           user.ID,
		Username:         user.Username,
		DisplayName:      user.DisplayName,
		Roles:            roleIDs,
		Permissions:      access.Permissions,
		PermissionScopes: access.PermissionScopes,
		Scope:            access.Scope,
	}, nil
}

func (s Session) ScopeFor(permission string) string {
	if scope := strings.TrimSpace(s.PermissionScopes[strings.TrimSpace(permission)]); scope != "" {
		return scope
	}
	return strings.TrimSpace(s.Scope)
}

// ValidateToken checks whether the provided token is still valid.
// 临近过期的会话会在校验时滑动续期，使持续使用的登录状态不掉线。
func (a *AuthManager) ValidateToken(token string) (Session, bool) {
	if strings.TrimSpace(token) == "" {
		return Session{}, false
	}

	a.mu.RLock()
	session, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return Session{}, false
	}

	now := time.Now()
	if now.After(session.ExpiresAt) {
		a.mu.Lock()
		delete(a.sessions, token)
		a.mu.Unlock()
		a.persist()
		return Session{}, false
	}

	if a.extendSessionIfNeeded(token, session, now) {
		a.mu.RLock()
		session, ok = a.sessions[token]
		a.mu.RUnlock()
		if !ok {
			return Session{}, false
		}
	}

	return session, true
}

// slidingRefreshWindow 返回开始考虑滑动续期的时间窗口（临近过期多久内）。
func (a *AuthManager) slidingRefreshWindow() time.Duration {
	window := a.sessionDuration / 4
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	if window <= 0 {
		window = time.Minute
	}
	return window
}

// slidingRefreshInterval 返回同一会话两次滑动续期之间的最小间隔。
// 用于避免每个请求都向持久化存储写入。
func (a *AuthManager) slidingRefreshInterval() time.Duration {
	interval := a.sessionDuration / 8
	if interval > time.Hour {
		interval = time.Hour
	}
	if interval <= 0 {
		interval = time.Minute
	}
	return interval
}

// extendSessionIfNeeded 在会话临近过期时把有效期延长一个完整周期。
// 返回是否真的发生了续期。
func (a *AuthManager) extendSessionIfNeeded(token string, session Session, now time.Time) bool {
	if session.ExpiresAt.Sub(now) > a.slidingRefreshWindow() {
		return false
	}
	if !session.LastRefreshedAt.IsZero() && now.Sub(session.LastRefreshedAt) < a.slidingRefreshInterval() {
		return false
	}

	a.mu.Lock()
	current, ok := a.sessions[token]
	if !ok {
		a.mu.Unlock()
		return false
	}
	// 拿锁期间会话可能已过期，避免把过期会话续活。
	if now.After(current.ExpiresAt) {
		a.mu.Unlock()
		return false
	}
	current.ExpiresAt = now.Add(a.sessionDuration)
	current.LastRefreshedAt = now
	a.sessions[token] = current
	a.mu.Unlock()

	a.persist()
	return true
}

// CheckPassword verifies whether the provided password matches the current password.
func (a *AuthManager) CheckPassword(password string) bool {
	return a.CheckUserPassword("admin", password)
}

// CheckUserPassword verifies whether the provided password matches a user.
func (a *AuthManager) CheckUserPassword(username, password string) bool {
	a.mu.RLock()
	db := a.db
	a.mu.RUnlock()
	if db == nil {
		return false
	}
	user, err := db.GetRBACUserByUsername(username)
	if err != nil {
		return false
	}
	return VerifyPasswordHash(password, user.PasswordHash)
}

func (a *AuthManager) UpdateUserPassword(userID, password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return errors.New("auth password must be configured")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	a.mu.RLock()
	db := a.db
	a.mu.RUnlock()
	if db == nil {
		return errors.New("authentication store is not configured")
	}
	if err := db.UpdateRBACUserPassword(userID, hash); err != nil {
		return err
	}
	a.mu.Lock()
	for token, session := range a.sessions {
		if session.UserID == userID {
			delete(a.sessions, token)
		}
	}
	a.mu.Unlock()
	a.persist()
	return nil
}

// RevokeToken invalidates the specified token.
func (a *AuthManager) RevokeToken(token string) {
	if strings.TrimSpace(token) == "" {
		return
	}

	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
	a.persist()
}

func (a *AuthManager) RevokeUserSessions(userID string) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return
	}
	a.mu.Lock()
	for token, session := range a.sessions {
		if session.UserID == userID {
			delete(a.sessions, token)
		}
	}
	a.mu.Unlock()
	a.persist()
}

func (a *AuthManager) RevokeAllSessions() {
	a.mu.Lock()
	a.sessions = make(map[string]Session)
	a.mu.Unlock()
	a.persist()
}

// SessionDurationHours returns the configured session duration in hours.
func (a *AuthManager) SessionDurationHours() int {
	return int(a.sessionDuration / time.Hour)
}

func allPermissions() map[string]bool {
	out := make(map[string]bool, len(PermissionCatalog))
	for key := range PermissionCatalog {
		out[key] = true
	}
	return out
}
