package database

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

func newAssetRelationsTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "asset-relations.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.initAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	return db
}

func assetRelationsTestProject(t *testing.T, db *DB, name, owner string) *Project {
	t.Helper()
	project, err := db.CreateProject(&Project{Name: name, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", project.ID, owner); err != nil {
		t.Fatal(err)
	}
	return project
}

func assetRelationCount(t *testing.T, db *DB, table string) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAssetRelationsRetainMultipleIPsAndProjects(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	pA := assetRelationsTestProject(t, db, "Original", "owner-a")
	pB := assetRelationsTestProject(t, db, "Additional", "owner-a")
	oldTime := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	first := &Asset{ProjectID: pA.ID, Domain: "shared.example.com", IP: "192.0.2.1", Port: 443, Protocol: "https", Source: "dns", SourceQuery: "original resolver",
		Observation: &AssetObservation{ID: "caller-id", AssetID: "foreign-asset", ProjectID: pB.ID, IP: "198.51.100.9", Source: "forged", ObservedAt: oldTime, ConversationID: "original-conversation", ExecutionID: "exec-a"}}
	if result, err := db.UpsertAssets([]*Asset{first}, "owner-a"); err != nil || result.Created != 1 {
		t.Fatalf("first create: %#v %v", result, err)
	}
	second := &Asset{ProjectID: pB.ID, Domain: first.Domain, IP: "192.0.2.2", Port: 443, Protocol: "https", Source: "fofa", SourceQuery: "second resolver"}
	if result, err := db.UpsertAssets([]*Asset{second}, "owner-a"); err != nil || result.Updated != 1 || second.ID != first.ID {
		t.Fatalf("shared service upsert: %#v %v id=%s", result, err, second.ID)
	}
	access := RBACListAccess{UserID: "owner-a", Scope: RBACScopeOwn}
	saved, err := db.GetAsset(first.ID, access)
	if err != nil || saved.ProjectID != pA.ID || saved.IP != first.IP {
		t.Fatalf("original project/IP overwritten: %#v %v", saved, err)
	}
	for _, project := range []*Project{pA, pB} {
		items, total, err := db.ListAssets(20, 0, AssetListFilter{ProjectID: project.ID}, access)
		if err != nil || total != 1 || len(items) != 1 || items[0].ID != first.ID {
			t.Fatalf("project %s list: total=%d items=%#v %v", project.Name, total, items, err)
		}
		if _, err := db.GetAssetForProject(first.ID, project.ID, access); err != nil {
			t.Fatalf("project relationship not visible to owner: %v", err)
		}
	}
	observations, total, err := db.ListAssetObservations(first.ID, 20, 0, access)
	if err != nil || total != 2 || len(observations) != 2 {
		t.Fatalf("observation history: total=%d items=%#v %v", total, observations, err)
	}
	byIP := map[string]*AssetObservation{}
	for _, observation := range observations {
		byIP[observation.IP] = observation
	}
	old := byIP[first.IP]
	if old == nil || old.ID == "caller-id" || old.AssetID != first.ID || old.ProjectID != pA.ID || old.Source != "dns" || old.SourceQuery != "original resolver" || !old.ObservedAt.Equal(oldTime) || old.ExecutionID != "exec-a" || old.ConversationID != "original-conversation" {
		t.Fatalf("lost original evidence: %#v", old)
	}
	if byIP[second.IP] == nil || byIP[second.IP].Source != "fofa" {
		t.Fatalf("lost new IP/source: %#v", byIP)
	}
	for _, filter := range []AssetListFilter{{IP: first.IP}, {IP: second.IP}, {Source: "dns"}, {Source: "fofa"}, {Search: second.IP}} {
		items, total, err := db.ListAssets(20, 0, filter, access)
		if err != nil || total != 1 || len(items) != 1 {
			t.Fatalf("historical filter %#v: total=%d items=%d %v", filter, total, len(items), err)
		}
	}
	scoped, total, err := db.ListAssetObservations(first.ID, 1, 0, access, pB.ID)
	if err != nil || total != 1 || len(scoped) != 1 || scoped[0].IP != second.IP {
		t.Fatalf("project evidence scope: %#v total=%d %v", scoped, total, err)
	}
	// Metadata updates retain the original relationship while recording the
	// explicit new IP, so the old endpoint is still searchable afterward.
	saved.ProjectID, saved.IP, saved.Source = pB.ID, "192.0.2.3", "manual"
	if err := db.UpdateAssetForProject(saved.ID, saved, access, pB.ID); err != nil {
		t.Fatal(err)
	}
	updated, err := db.GetAsset(saved.ID, access)
	if err != nil || updated.ProjectID != pA.ID || updated.IP != "192.0.2.3" {
		t.Fatalf("explicit update lost primary project: %#v %v", updated, err)
	}
	if _, total, err := db.ListAssetObservations(first.ID, 20, 0, access); err != nil || total != 3 {
		t.Fatalf("explicit update discarded evidence: total=%d %v", total, err)
	}
}

func TestAssetRelationsNeverGrantCrossUserPermission(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	userA, err := db.CreateRBACUser("relations-a", "A", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := db.CreateRBACUser("relations-b", "B", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	pA := assetRelationsTestProject(t, db, "Private A", userA.ID)
	pB := assetRelationsTestProject(t, db, "Private B", userB.ID)
	asset := &Asset{ProjectID: pA.ID, Domain: "private.example.com", Port: 443, Protocol: "https", Title: "Private"}
	if _, err := db.UpsertAssets([]*Asset{asset}, userA.ID); err != nil {
		t.Fatal(err)
	}
	// A global operator can associate an existing entity, but cannot grant
	// the destination project's owner any additional asset permissions.
	link := &Asset{ProjectID: pB.ID, Domain: asset.Domain, Port: 443, Protocol: "https", Source: "global"}
	if _, err := db.UpsertAssets([]*Asset{link}, userA.ID, true); err != nil {
		t.Fatal(err)
	}
	accessB := RBACListAccess{UserID: userB.ID, Scope: RBACScopeOwn}
	if db.UserCanAccessResource(userB.ID, RBACScopeOwn, "asset", asset.ID) {
		t.Fatal("project relationship widened asset authorization")
	}
	if _, err := db.GetAssetForProject(asset.ID, pB.ID, accessB); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign project owner can get shared service: %v", err)
	}
	if _, total, err := db.ListAssets(20, 0, AssetListFilter{ProjectID: pB.ID}, accessB); err != nil || total != 0 {
		t.Fatalf("foreign project owner can list service: total=%d %v", total, err)
	}
	if _, _, err := db.ListAssetObservations(asset.ID, 20, 0, accessB); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign owner can read evidence: %v", err)
	}
	foreign := &Asset{ProjectID: pB.ID, Domain: asset.Domain, Port: 443, Protocol: "https", Title: "Hijacked", IP: "198.51.100.99"}
	before := assetRelationCount(t, db, "asset_observations")
	if result, err := db.UpsertAssets([]*Asset{foreign}, userB.ID); err != nil || result.Skipped != 1 || foreign.ID != "" {
		t.Fatalf("conflict bypassed owner check: %#v id=%s %v", result, foreign.ID, err)
	}
	if err := db.UpdateAsset(asset.ID, foreign, accessB); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign update allowed: %v", err)
	}
	if assetRelationCount(t, db, "asset_observations") != before {
		t.Fatal("unauthorized conflict left evidence")
	}
	var assignmentCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rbac_resource_assignments WHERE user_id=? AND resource_type='asset'`, userB.ID).Scan(&assignmentCount); err != nil || assignmentCount != 0 {
		t.Fatalf("conflict synthesized permission: %d %v", assignmentCount, err)
	}
	// Existing explicit asset authorization remains usable; relationships
	// themselves are still not treated as an owner/import permission.
	if err := db.AssignResourceToUser(userB.ID, "asset", asset.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetAssetForProject(asset.ID, pB.ID, accessB); err != nil {
		t.Fatalf("existing explicit authorization was lost: %v", err)
	}
	if result, err := db.UpsertAssets([]*Asset{foreign}, userB.ID); err != nil || result.Skipped != 1 {
		t.Fatalf("assignment bypassed strict upsert ownership: %#v %v", result, err)
	}
	// An owned asset cannot be used to write into someone else's project.
	own := &Asset{Domain: "new-private.example.com", ProjectID: pA.ID}
	if _, err := db.UpsertAssets([]*Asset{own}, userB.ID); err == nil || own.ID != "" {
		t.Fatalf("foreign project create accepted: id=%s %v", own.ID, err)
	}
	if assetRelationCount(t, db, "assets") != 1 {
		t.Fatal("rejected project create left an asset")
	}
}

func TestAssetUpsertConcurrentSharedService(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	db.SetMaxOpenConns(8)
	pA := assetRelationsTestProject(t, db, "Concurrent A", "concurrent-owner")
	pB := assetRelationsTestProject(t, db, "Concurrent B", "concurrent-owner")
	// A second handle proves this works without a per-DB/process mutex.
	var path string
	if err := db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	other, err := Open(OpenOptions{Path: path, Dialect: DialectSQLite, SkipInit: true, Logger: zap.NewNop()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	other.SetMaxOpenConns(8)
	const workers = 32
	assets := make([]*Asset, workers)
	results := make([]AssetImportResult, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		projectID := pA.ID
		handle := db
		if i%2 == 1 {
			projectID, handle = pB.ID, other
		}
		assets[i] = &Asset{ProjectID: projectID, Domain: "concurrent.example.com", IP: fmt.Sprintf("192.0.2.%d", i+1), Port: 443, Protocol: "https", Source: "dns"}
		wg.Add(1)
		go func(i int, handle *DB) {
			defer wg.Done()
			<-start
			results[i], errs[i] = handle.UpsertAssets([]*Asset{assets[i]}, "concurrent-owner")
		}(i, handle)
	}
	close(start)
	wg.Wait()
	var created, updated int
	for i := range assets {
		if errs[i] != nil || results[i].Skipped != 0 || assets[i].ID == "" || assets[i].ID != assets[0].ID {
			t.Fatalf("worker %d: %#v id=%s %v", i, results[i], assets[i].ID, errs[i])
		}
		created += results[i].Created
		updated += results[i].Updated
	}
	if created != 1 || updated != workers-1 || assetRelationCount(t, db, "assets") != 1 || assetRelationCount(t, db, "asset_project_links") != 2 {
		t.Fatalf("concurrent counts: created=%d updated=%d", created, updated)
	}
	observations, total, err := db.ListAssetObservations(assets[0].ID, 100, 0, RBACListAccess{Scope: RBACScopeAll})
	if err != nil || total != workers || len(observations) != workers {
		t.Fatalf("concurrent evidence missing: total=%d %v", total, err)
	}
	ips := map[string]bool{}
	for _, observation := range observations {
		ips[observation.IP] = true
	}
	if len(ips) != workers {
		t.Fatalf("only %d of %d IP observations survived", len(ips), workers)
	}
}

func TestAssetUpsertConcurrentOwnersCannotHijack(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	db.SetMaxOpenConns(8)
	pA := assetRelationsTestProject(t, db, "Owner A", "owner-a")
	pB := assetRelationsTestProject(t, db, "Owner B", "owner-b")
	const workers = 16
	assets := make([]*Asset, workers)
	results := make([]AssetImportResult, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		owner, project := "owner-a", pA.ID
		if i%2 == 1 {
			owner, project = "owner-b", pB.ID
		}
		assets[i] = &Asset{ProjectID: project, Domain: "race-owners.example.com", IP: fmt.Sprintf("198.51.100.%d", i+1), Port: 443, Protocol: "https", Source: owner}
		wg.Add(1)
		go func(i int, owner string) {
			defer wg.Done()
			<-start
			results[i], errs[i] = db.UpsertAssets([]*Asset{assets[i]}, owner)
		}(i, owner)
	}
	close(start)
	wg.Wait()
	created, updated, skipped := 0, 0, 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("owner worker %d failed: %v", i, errs[i])
		}
		if results[i].Skipped == 1 && assets[i].ID != "" {
			t.Fatal("unauthorized conflict exposed the private asset ID")
		}
		created += results[i].Created
		updated += results[i].Updated
		skipped += results[i].Skipped
	}
	if created != 1 || updated != workers/2-1 || skipped != workers/2 || assetRelationCount(t, db, "asset_project_links") != 1 || assetRelationCount(t, db, "asset_observations") != workers/2 {
		t.Fatalf("foreign writes escaped owner boundary: created=%d updated=%d skipped=%d", created, updated, skipped)
	}
}

func TestAssetRelationsWriteFailureRollsBackEverything(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	p := assetRelationsTestProject(t, db, "Atomic", "owner")
	if _, err := db.Exec(`CREATE TRIGGER fail_asset_observation BEFORE INSERT ON asset_observations
		WHEN NEW.source='reject' BEGIN SELECT RAISE(ABORT,'forced observation failure'); END`); err != nil {
		t.Fatal(err)
	}
	assets := []*Asset{
		{ProjectID: p.ID, Domain: "a-atomic.example.com", IP: "192.0.2.10", Source: "dns"},
		{ProjectID: p.ID, Domain: "z-atomic.example.com", IP: "192.0.2.11", Source: "reject"},
	}
	result, err := db.UpsertAssets(assets, "owner")
	if err == nil || result != (AssetImportResult{}) || assets[0].ID != "" || assets[1].ID != "" {
		t.Fatalf("partial success reported: result=%#v assets=%#v %v", result, assets, err)
	}
	for _, table := range []string{"assets", "asset_project_links", "asset_observations"} {
		if n := assetRelationCount(t, db, table); n != 0 {
			t.Fatalf("failed transaction left %d rows in %s", n, table)
		}
	}
	if _, err := db.UpsertAssets(assets[:1], "owner"); err != nil {
		t.Fatal(err)
	}
	p2 := assetRelationsTestProject(t, db, "Update destination", "owner")
	patch := *assets[0]
	patch.ProjectID, patch.IP, patch.Source, patch.Title = p2.ID, "192.0.2.99", "reject", "must rollback"
	if err := db.UpdateAsset(patch.ID, &patch, RBACListAccess{UserID: "owner", Scope: RBACScopeOwn}); err == nil {
		t.Fatal("failed observation update was accepted")
	}
	saved, err := db.GetAsset(assets[0].ID, RBACListAccess{Scope: RBACScopeAll})
	if err != nil || saved.IP != "192.0.2.10" || saved.Title != "" || saved.ProjectID != p.ID || assetRelationCount(t, db, "asset_project_links") != 1 || assetRelationCount(t, db, "asset_observations") != 1 {
		t.Fatalf("failed update left partial state: %#v %v", saved, err)
	}
}

func TestAssetRelationsLegacyMigrationIsIdempotent(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "legacy-assets.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := assetRelationsTestProject(t, db, "Legacy", "owner-a")
	now := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	// A deliberately old-format key must be retained byte for byte.
	key := "original-legacy-dedup-key"
	if _, err := db.Exec(`INSERT INTO assets (id,dedup_key,project_id,ip,source,source_query,first_seen_at,last_seen_at,created_at,updated_at,owner_user_id)
		VALUES ('legacy-private',?,?,'192.0.2.50','legacy-provider','legacy query',?,?,?,?,'owner-a')`, key, p.ID, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets (id,dedup_key,ip,source,first_seen_at,last_seen_at,created_at,updated_at)
		VALUES ('legacy-unbound','unbound-key','192.0.2.51','manual',?,?,?,?)`, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	assignmentsBefore := assetRelationCount(t, db, "rbac_resource_assignments")
	for i := 0; i < 2; i++ {
		if err := db.initAssetRelationsTables(); err != nil {
			t.Fatal(err)
		}
	}
	if assetRelationCount(t, db, "asset_project_links") != 1 || assetRelationCount(t, db, "asset_observations") != 2 || assetRelationCount(t, db, "rbac_resource_assignments") != assignmentsBefore {
		t.Fatal("migration duplicated records or created authorization grants")
	}
	var savedKey string
	if err := db.QueryRow(`SELECT dedup_key FROM assets WHERE id='legacy-private'`).Scan(&savedKey); err != nil || savedKey != key {
		t.Fatalf("migration changed legacy identity: %q %v", savedKey, err)
	}
	observations, total, err := db.ListAssetObservations("legacy-private", 20, 0, RBACListAccess{Scope: RBACScopeAll})
	if err != nil || total != 1 || observations[0].SourceQuery != "legacy query" || !observations[0].ObservedAt.Equal(now) || observations[0].ID != "legacy:legacy-private" {
		t.Fatalf("migration lost legacy evidence: %#v total=%d %v", observations, total, err)
	}
	if _, err := db.GetAssetForProject("legacy-private", p.ID, RBACListAccess{UserID: "owner-a", Scope: RBACScopeOwn}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetAssetForProject("legacy-private", p.ID, RBACListAccess{UserID: "owner-b", Scope: RBACScopeOwn}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("legacy migration widened visibility: %v", err)
	}
	modern := &Asset{IP: "192.0.2.52", Source: "modern"}
	if _, err := db.UpsertAssets([]*Asset{modern}, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if err := db.initAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	if assetRelationCount(t, db, "asset_observations") != 3 {
		t.Fatal("restart manufactured a legacy observation for a modern asset")
	}
}

func TestAssetRelationsMergePreservesEvidenceAndDeleteCascades(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	pA := assetRelationsTestProject(t, db, "Merge A", "owner")
	pB := assetRelationsTestProject(t, db, "Merge B", "owner")
	assets := []*Asset{
		{ProjectID: pA.ID, Domain: "merge-relations.example.com", IP: "192.0.2.1", Port: 80, Source: "dns"},
		{ProjectID: pB.ID, Domain: "merge-relations.example.com", IP: "192.0.2.2", Port: 443, Source: "fofa"},
	}
	if _, err := db.UpsertAssets(assets, "owner"); err != nil {
		t.Fatal(err)
	}
	access := RBACListAccess{UserID: "owner", Scope: RBACScopeOwn}
	if merged, err := db.MergeAssets(assets[0], []string{assets[1].ID}, access, access); err != nil || merged != 1 {
		t.Fatalf("merge relations: merged=%d %v", merged, err)
	}
	if _, err := db.GetAssetForProject(assets[0].ID, pB.ID, access); err != nil {
		t.Fatalf("merge dropped duplicate's project: %v", err)
	}
	items, total, err := db.ListAssetObservations(assets[0].ID, 20, 0, access)
	if err != nil || total != 2 || len(items) != 2 || assetRelationCount(t, db, "asset_project_links") != 2 {
		t.Fatalf("merge dropped evidence: total=%d %v", total, err)
	}
	if err := db.DeleteAsset(assets[0].ID, access); err != nil {
		t.Fatal(err)
	}
	if assetRelationCount(t, db, "asset_observations") != 0 || assetRelationCount(t, db, "asset_project_links") != 0 {
		t.Fatal("delete left orphaned asset relationships")
	}
}

func TestAssetRelationsProjectBindingIsAdditiveAndAtomic(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	pA := assetRelationsTestProject(t, db, "First binding", "owner")
	pB := assetRelationsTestProject(t, db, "Second binding", "owner")
	pC := assetRelationsTestProject(t, db, "Foreign binding", "other-owner")
	asset := &Asset{Domain: "binding.example.com", IP: "192.0.2.90"}
	if _, err := db.UpsertAssets([]*Asset{asset}, "owner"); err != nil {
		t.Fatal(err)
	}
	access := RBACListAccess{UserID: "owner", Scope: RBACScopeOwn}
	for _, project := range []*Project{pA, pB} {
		if n, err := db.UpdateAssetsProject([]string{asset.ID}, project.ID, access); err != nil || n != 1 {
			t.Fatalf("add binding: count=%d %v", n, err)
		}
	}
	saved, err := db.GetAsset(asset.ID, access)
	if err != nil || saved.ProjectID != pA.ID || assetRelationCount(t, db, "asset_project_links") != 2 {
		t.Fatalf("second binding replaced original: %#v %v", saved, err)
	}
	if _, err := db.UpdateAssetsProject([]string{asset.ID}, pC.ID, access); err == nil {
		t.Fatal("bulk binding crossed project authorization")
	}
	if _, err := db.UpdateAssetsProject([]string{asset.ID, "missing"}, "", access); err == nil {
		t.Fatal("partial unbind unexpectedly succeeded")
	}
	// Even a globally authorized writer cannot bypass the explicit
	// conversation-project membership check in the database mutation.
	patch := *saved
	patch.ProjectID, patch.Title = pC.ID, "must rollback"
	if err := db.UpdateAssetForProject(saved.ID, &patch, RBACListAccess{Scope: RBACScopeAll}, pC.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("scoped update added foreign membership: %v", err)
	}
	if assetRelationCount(t, db, "asset_project_links") != 2 || assetRelationCount(t, db, "asset_observations") != 1 {
		t.Fatal("rejected binding/update changed relationships or evidence")
	}
	if _, err := db.UpdateAssetsProject([]string{asset.ID}, "", access); err != nil {
		t.Fatal(err)
	}
	saved, err = db.GetAsset(asset.ID, access)
	if err != nil || saved.ProjectID != "" || assetRelationCount(t, db, "asset_project_links") != 0 || assetRelationCount(t, db, "asset_observations") != 1 {
		t.Fatalf("explicit unbind lost evidence: %#v %v", saved, err)
	}
}

func TestAssetRelationsOwnerlessPrivateLegacyAssetIsNotPublic(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	pA := assetRelationsTestProject(t, db, "Private legacy A", "owner-a")
	pB := assetRelationsTestProject(t, db, "Private legacy B", "owner-b")
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO assets (id,dedup_key,project_id,domain,ip,port,protocol,source,first_seen_at,last_seen_at,created_at,updated_at)
		VALUES ('ownerless-private','ownerless.example.com|443|https',?,'ownerless.example.com','192.0.2.70',443,'https','legacy',?,?,?,?)`, pA.ID, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.initAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	foreign := &Asset{ProjectID: pB.ID, Domain: "ownerless.example.com", IP: "192.0.2.71", Port: 443, Protocol: "https", Source: "foreign", Title: "hijacked"}
	result, err := db.UpsertAssets([]*Asset{foreign}, "owner-b")
	if err != nil || result.Skipped != 1 || foreign.ID != "" {
		t.Fatalf("ownerless private legacy row treated as public: %#v id=%s %v", result, foreign.ID, err)
	}
	saved, err := db.GetAsset("ownerless-private", RBACListAccess{Scope: RBACScopeAll})
	if err != nil || saved.ProjectID != pA.ID || saved.IP != "192.0.2.70" || saved.Source != "legacy" || assetRelationCount(t, db, "asset_project_links") != 1 || assetRelationCount(t, db, "asset_observations") != 1 {
		t.Fatalf("foreign legacy upsert changed private state: %#v %v", saved, err)
	}
}

func TestAssetTransactionRetriesWholeTransaction(t *testing.T) {
	for _, errCase := range []struct {
		name string
		err  error
	}{
		{"pg-serialization", &pgconn.PgError{Code: "40001"}},
		{"pg-deadlock", &pgconn.PgError{Code: "40P01"}},
		{"sqlite-busy", sqlite3.Error{Code: sqlite3.ErrBusy}},
		{"sqlite-locked", sqlite3.Error{Code: sqlite3.ErrLocked}},
	} {
		t.Run(errCase.name, func(t *testing.T) {
			db := newAssetRelationsTestDB(t)
			if _, err := db.Exec(`CREATE TABLE asset_retry_probe (value INTEGER)`); err != nil {
				t.Fatal(err)
			}
			calls := 0
			err := db.withAssetTransaction(func(tx *Tx) error {
				calls++
				if _, err := tx.Exec(`INSERT INTO asset_retry_probe VALUES (1)`); err != nil {
					return err
				}
				if calls == 1 {
					return fmt.Errorf("wrapped: %w", errCase.err)
				}
				return nil
			})
			if err != nil || calls != 2 || assetRelationCount(t, db, "asset_retry_probe") != 1 {
				t.Fatalf("retry did not roll back/restart: calls=%d %v", calls, err)
			}
		})
	}
}

func TestAssetTransactionRetryIsBoundedAndPermissionErrorsAreFinal(t *testing.T) {
	db := newAssetRelationsTestDB(t)
	calls := 0
	busy := sqlite3.Error{Code: sqlite3.ErrBusy}
	err := db.withAssetTransaction(func(*Tx) error { calls++; return busy })
	if err == nil || calls != assetTransactionAttempts {
		t.Fatalf("unbounded retry: calls=%d %v", calls, err)
	}
	for _, finalErr := range []error{sql.ErrNoRows, &pgconn.PgError{Code: "23505"}, assetValidationErrorf("invalid"), errors.New("permission denied")} {
		calls = 0
		err := db.withAssetTransaction(func(*Tx) error { calls++; return finalErr })
		if !errors.Is(err, finalErr) || calls != 1 {
			t.Fatalf("retried permanent failure: calls=%d %v", calls, err)
		}
	}
}

func TestAssetRelationsPostgresSQLCompatibility(t *testing.T) {
	for _, ddl := range []string{assetProjectLinksDDL, assetObservationsDDL} {
		adapted := DialectPostgres.Adapt(ddl)
		if strings.Contains(adapted, "DATETIME") || !strings.Contains(adapted, "TIMESTAMPTZ") || !strings.Contains(adapted, "ON DELETE CASCADE") {
			t.Fatalf("incompatible Postgres schema: %s", adapted)
		}
	}
	query := DialectPostgres.Adapt(assetInsertSQL)
	if strings.Contains(query, "?") || !strings.Contains(query, "$27") || !strings.Contains(query, "ON CONFLICT (dedup_key) DO NOTHING") || strings.Contains(query, "DO UPDATE") {
		t.Fatalf("unsafe/incompatible Postgres upsert: %s", query)
	}
	if (&DB{dialect: DialectPostgres}).assetRowLock() != " FOR UPDATE" || (&DB{dialect: DialectSQLite}).assetRowLock() != "" {
		t.Fatal("dialect-specific locking is wrong")
	}
}
