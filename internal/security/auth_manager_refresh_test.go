package security

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"cyberstrike-ai/internal/cache"
	"cyberstrike-ai/internal/database"
)

func TestValidateTokenRefreshesRestoredPermissions(t *testing.T) {
	db := seedPersistTestDB(t)
	store := cache.NewMemory()
	before := newPersistTestManager(t, db, store, 168)
	token, expiresAt, err := before.Authenticate("admin", "bootstrap-admin-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// A previous release knew neither permission. Redis preserves that snapshot.
	before.mu.Lock()
	old := before.sessions[token]
	delete(old.Permissions, "experience:read")
	delete(old.Permissions, "target:read")
	delete(old.PermissionScopes, "experience:read")
	delete(old.PermissionScopes, "target:read")
	before.sessions[token] = old
	before.mu.Unlock()
	before.persist()

	after := newPersistTestManager(t, db, store, 168)
	session, ok := after.ValidateToken(token)
	if !ok {
		t.Fatal("existing enabled user's session must survive the release")
	}
	if !session.Permissions["experience:read"] || !session.Permissions["target:read"] {
		t.Fatal("restored permissions must be resolved from current database roles")
	}
	if session.ScopeFor("experience:read") != database.RBACScopeAll {
		t.Fatalf("refreshed experience scope = %q", session.ScopeFor("experience:read"))
	}
	if session.Token != token || !session.ExpiresAt.Equal(expiresAt) {
		t.Fatal("permission refresh must preserve the token and unrelated expiry")
	}
	payload, ok := store.Get(context.Background(), sessionPersistKey)
	if !ok {
		t.Fatal("refreshed session was not persisted")
	}
	var stored map[string]Session
	if err := json.Unmarshal(payload, &stored); err != nil {
		t.Fatalf("decode persisted session: %v", err)
	}
	if !stored[token].Permissions["experience:read"] || !stored[token].Permissions["target:read"] {
		t.Fatal("persisted permissions must not retain the old release snapshot")
	}
}

func TestValidateTokenRefreshesRolesAndPermissionSpecificScopes(t *testing.T) {
	manager, db, _, token := newSlidingTestManager(t, 12)
	initial, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("initial token must validate")
	}
	chatRole, err := db.UpsertRBACRole("", "Global chat", "", database.RBACScopeAll, []string{"chat:read"})
	if err != nil {
		t.Fatalf("create chat role: %v", err)
	}
	experienceRole, err := db.UpsertRBACRole("", "Assigned experience", "", database.RBACScopeAssigned, []string{"experience:read"})
	if err != nil {
		t.Fatalf("create experience role: %v", err)
	}
	roles := []string{chatRole.ID, experienceRole.ID}
	if err := db.UpdateRBACUser(initial.UserID, "Renamed Operator", nil, &roles); err != nil {
		t.Fatalf("update user's roles: %v", err)
	}
	refreshed, ok := manager.ValidateToken(token)
	if !ok {
		t.Fatal("enabled user's token must still validate")
	}
	if refreshed.DisplayName != "Renamed Operator" || len(refreshed.Roles) != 2 {
		t.Fatal("current profile and roles must replace cached metadata")
	}
	if !refreshed.Permissions["experience:read"] || refreshed.Permissions["asset:read"] {
		t.Fatal("refresh must both grant current permissions and remove revoked permissions")
	}
	if refreshed.Scope != database.RBACScopeAll || refreshed.ScopeFor("experience:read") != database.RBACScopeAssigned || refreshed.ScopeFor("chat:read") != database.RBACScopeAll {
		t.Fatal("global permissions must not expand another permission's resource scope")
	}
	if _, err := db.UpsertRBACRole(experienceRole.ID, experienceRole.Name, "", database.RBACScopeOwn, nil); err != nil {
		t.Fatalf("revoke experience permission: %v", err)
	}
	refreshed, ok = manager.ValidateToken(token)
	if !ok || refreshed.Permissions["experience:read"] {
		t.Fatal("subsequent validation must observe role permission removal")
	}
	if _, exists := refreshed.PermissionScopes["experience:read"]; exists {
		t.Fatal("removed permission must not keep its old scope")
	}
}

func TestValidateTokenRejectsInvalidRestoredIdentity(t *testing.T) {
	for _, scenario := range []string{"disabled", "deleted", "missing_user_id", "unknown_user_id"} {
		t.Run(scenario, func(t *testing.T) {
			manager, db, store, token := newSlidingTestManager(t, 12)
			manager.mu.RLock()
			session := manager.sessions[token]
			manager.mu.RUnlock()
			switch scenario {
			case "disabled":
				disabled := false
				if err := db.UpdateRBACUser(session.UserID, session.DisplayName, &disabled, nil); err != nil {
					t.Fatalf("disable user: %v", err)
				}
			case "deleted":
				if err := db.DeleteRBACUser(session.UserID); err != nil {
					t.Fatalf("delete user: %v", err)
				}
			case "missing_user_id", "unknown_user_id":
				// Even an admin-looking snapshot cannot substitute a username for identity.
				session.UserID = ""
				if scenario == "unknown_user_id" {
					session.UserID = "no-such-user"
				}
				session.Username = "admin"
				session.Roles = []string{database.RBACSystemRoleAdmin}
				session.Permissions = allPermissions()
				manager.mu.Lock()
				manager.sessions[token] = session
				manager.mu.Unlock()
			}
			manager.persist()
			if _, ok := manager.ValidateToken(token); ok {
				t.Fatal("invalid identity must never use persisted permission grants")
			}
			restarted := newPersistTestManager(t, db, store, 12)
			if _, ok := restarted.ValidateToken(token); ok {
				t.Fatal("invalid session must not return after restart")
			}
			restarted.mu.RLock()
			_, retained := restarted.sessions[token]
			restarted.mu.RUnlock()
			if retained {
				t.Fatal("permanently invalid session must be removed from storage")
			}
		})
	}
}

func TestValidateTokenFailsClosedWhenAccessStoreIsUnavailable(t *testing.T) {
	manager, db, _, token := newSlidingTestManager(t, 12)
	if err := db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if _, ok := manager.ValidateToken(token); ok {
		t.Fatal("unavailable database must not authorize from stale cached grants")
	}
	manager.mu.RLock()
	_, retained := manager.sessions[token]
	manager.mu.RUnlock()
	if !retained {
		t.Fatal("transient access lookup failure must not permanently revoke the session")
	}
}

type countingSessionStore struct {
	cache.Store
	writes int
}

func (s *countingSessionStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	s.writes++
	s.Store.Set(ctx, key, value, ttl)
}

func TestValidateTokenDoesNotPersistUnchangedPermissions(t *testing.T) {
	db := seedPersistTestDB(t)
	store := &countingSessionStore{Store: cache.NewMemory()}
	manager := newPersistTestManager(t, db, store, 12)
	token, _, err := manager.Authenticate("operator1", "operator-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	writes := store.writes
	for range 3 {
		if _, ok := manager.ValidateToken(token); !ok {
			t.Fatal("unchanged session should validate")
		}
	}
	if store.writes != writes {
		t.Fatalf("unchanged permissions caused %d redundant persistence writes", store.writes-writes)
	}
}
