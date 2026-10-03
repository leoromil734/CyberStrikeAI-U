// validate-results runs migrations and concurrency checks only on an explicitly
// named csai_validation_* PostgreSQL database. It never scans or runs a POC.
package main

import (
	"context"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	name := flag.String("dbname", "", "isolated csai_validation_* database name")
	host := flag.String("host", "/var/run/postgresql", "Unix socket directory")
	user := flag.String("user", "cyberstrike", "existing database role")
	flag.Parse()
	if !regexp.MustCompile(`^csai_validation_[a-z0-9_]+$`).MatchString(*name) {
		fail(fmt.Errorf("refusing non-validation database"))
	}
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable", *host, *user, *name)
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		fail(err)
	}
	preserved := map[string]int64{}
	var actualName string
	if err := raw.QueryRow(`SELECT current_database()`).Scan(&actualName); err != nil || actualName != *name {
		fail(fmt.Errorf("refusing a mismatched actual database"))
	}
	for _, table := range []string{"batch_tasks", "vulnerabilities", "project_facts", "tool_executions"} {
		var n int64
		if err = raw.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			fail(err)
		}
		preserved[table] = n
	}
	raw.Close()
	opts := database.OpenOptions{Dialect: database.DialectPostgres, DSN: dsn, ArtifactsBaseDir: os.TempDir(), Logger: zap.NewNop()}
	db, err := database.Open(opts)
	if err != nil {
		fail(err)
	}
	db.Close()
	db, err = database.Open(opts)
	if err != nil {
		fail(err)
	}
	defer db.Close()
	for table, before := range preserved {
		var after int64
		if err = db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&after); err != nil || before != after {
			fail(fmt.Errorf("migration altered historical %s rows", table))
		}
	}
	owner := "csai_validation_" + uuid.NewString()
	projects := []string{}
	for i := 0; i < 2; i++ {
		p, err := db.CreateProject(&database.Project{Name: owner + fmt.Sprint(i)})
		if err != nil {
			fail(err)
		}
		if err = db.SetResourceOwner("project", p.ID, owner); err != nil {
			fail(err)
		}
		projects = append(projects, p.ID)
	}
	hostName := uuid.NewString() + ".invalid"
	var created, updated atomic.Int64
	failures := make(chan error, 64)
	ids := make(chan string, 64)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := &database.Asset{ProjectID: projects[i%2], Host: hostName, Domain: hostName, IP: fmt.Sprintf("192.0.2.%d", i%8+1), Port: 443, Protocol: "https", Status: "inactive", Source: "validation", Observation: &database.AssetObservation{ExecutionID: fmt.Sprintf("validation-%d", i)}}
			r, err := db.UpsertAssets([]*database.Asset{a}, owner)
			if err != nil {
				failures <- err
				return
			}
			created.Add(int64(r.Created))
			updated.Add(int64(r.Updated))
			ids <- a.ID
		}(i)
	}
	wg.Wait()
	close(failures)
	close(ids)
	for err := range failures {
		fail(err)
	}
	if created.Load() != 1 || updated.Load() != 63 {
		fail(fmt.Errorf("wrong upsert counts: created=%d updated=%d", created.Load(), updated.Load()))
	}
	assetID := ""
	for id := range ids {
		if assetID != "" && assetID != id {
			fail(fmt.Errorf("concurrent import produced duplicate identity"))
		}
		assetID = id
	}
	var links, observations, ips int
	if err = db.QueryRow(`SELECT COUNT(*) FROM asset_project_links WHERE asset_id=?`, assetID).Scan(&links); err != nil {
		fail(err)
	}
	if err = db.QueryRow(`SELECT COUNT(*),COUNT(DISTINCT ip) FROM asset_observations WHERE asset_id=?`, assetID).Scan(&observations, &ips); err != nil {
		fail(err)
	}
	if links != 2 || observations != 64 || ips != 8 {
		fail(fmt.Errorf("lost associations/observations: %d/%d/%d", links, observations, ips))
	}
	now := time.Now().UTC()
	e := evidence.Execution{ID: uuid.NewString(), Access: evidence.Access{ProjectID: projects[0], ConversationID: uuid.NewString(), Owner: owner}, ScopeID: "scope-validation", AssessmentID: "validation", Tool: "httpx", Status: "completed", Completion: evidence.Complete, StartedAt: now, FinishedAt: now}
	ctx := evidence.WithAccess(context.Background(), e.Access)
	dir, err := os.MkdirTemp("", "csai_validation_artifacts-")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(dir)
	output := filepath.Join(dir, "httpx.jsonl")
	if err = os.WriteFile(output, []byte(`{"url":"https://validation.invalid:443/api?route=account&format=json","host":"192.0.2.1"}`+"\n"), 0600); err != nil {
		fail(err)
	}
	registry, err := evidence.NewRegistry(db, []evidence.ManagedRoot{{Path: dir, Access: e.Access, ExecutionID: e.ID}}, 0)
	if err != nil {
		fail(err)
	}
	defer registry.Close()
	processor := recon.Processor{Store: db, Artifacts: registry}
	event := recon.Event{Execution: e, Artifacts: []evidence.Candidate{{Path: output, Kind: "output", Format: "jsonl", Completion: evidence.Complete}}}
	first, err := processor.Observe(ctx, event)
	if err != nil {
		fail(err)
	}
	second, err := processor.Observe(ctx, event)
	if err != nil {
		fail(err)
	}
	if first.Inventory.Endpoints != 1 || first.Inserted.Endpoints != 1 || second.Inserted.Total() != 0 {
		fail(fmt.Errorf("PostgreSQL inventory idempotency failed"))
	}
	if _, err = db.ResultExecution(evidence.WithAccess(ctx, evidence.Access{ProjectID: projects[1], ConversationID: e.ConversationID, Owner: e.Owner}), e.ID); err == nil {
		fail(fmt.Errorf("cross-project execution access was allowed"))
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"migrations_repeated": 2, "historical_rows_preserved": preserved, "concurrent_upserts": 64, "created": created.Load(), "updated": updated.Load(), "project_links": links, "observations": observations, "unique_ips": ips, "inventory_idempotent": true, "cross_project_denied": true, "network_scans": 0})
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
