package security

import (
	"path/filepath"
	"testing"

	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

func TestExperienceSystemRolePublicationPermissions(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "experience-policy.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.BootstrapRBAC("test-only-hash", PermissionCatalog); err != nil {
		t.Fatal(err)
	}
	u, err := db.CreateRBACUser("memory-operator", "Operator", "test-only-hash", true, []string{database.RBACSystemRoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	access, err := db.ResolveRBACAccess(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !access.Permissions["experience:read"] || !access.Permissions["experience:write"] {
		t.Fatal("operator cannot access normal memory operations")
	}
	for _, permission := range []string{"experience:review", "experience:share", "experience:export"} {
		if access.Permissions[permission] {
			t.Fatalf("operator gained publication permission %s", permission)
		}
	}
}
