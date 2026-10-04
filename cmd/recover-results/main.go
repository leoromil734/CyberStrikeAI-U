// recover-results only reprocesses saved tool results. It never starts the Web
// service, task scheduler, an agent, or a scanner. --apply is required to write.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/app"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "existing deployment configuration")
	idsFile := flag.String("ids-file", "", "JSON array of explicit execution IDs; no implicit all-failures mode")
	apply := flag.Bool("apply", false, "requeue and actually reparse only the supplied IDs")
	timeout := flag.Duration("timeout", 15*time.Minute, "total offline replay deadline")
	flag.Parse()
	if *idsFile == "" || *timeout <= 0 {
		return fmt.Errorf("--ids-file and a positive --timeout are required")
	}
	rawIDs, err := os.ReadFile(*idsFile)
	if err != nil {
		return err
	}
	var ids []string
	if err := json.Unmarshal(rawIDs, &ids); err != nil {
		return fmt.Errorf("invalid execution ID list: %w", err)
	}
	if len(ids) == 0 || len(ids) > 1000 {
		return fmt.Errorf("supply between 1 and 1000 explicit execution IDs")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || len(id) > 256 || seen[id] {
			return fmt.Errorf("empty, duplicate or invalid execution ID")
		}
		seen[id] = true
	}
	path, err := filepath.Abs(*configPath)
	if err != nil {
		return err
	}
	rawConfig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Only parse fields used for DB and managed originals. config.Load also
	// configures unrelated runtime tools/channels, which maintenance does not need.
	var cfg config.Config
	if err := yaml.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if err := os.Chdir(filepath.Dir(path)); err != nil {
		return err
	}
	if cfg.Database.Driver == "" || cfg.Database.Driver == "sqlite" {
		if cfg.Database.Path == "" {
			cfg.Database.Path = "data/conversations.db"
		}
		if _, err := os.Stat(cfg.Database.Path); err != nil {
			return fmt.Errorf("existing SQLite database required: %w", err)
		}
	}
	logger := zap.NewNop()
	db, err := database.Open(database.OpenOptions{Dialect: database.Dialect(cfg.Database.Driver), Path: cfg.Database.Path,
		DSN: cfg.Database.DSN, Host: cfg.Database.Host, Port: cfg.Database.Port, User: cfg.Database.User,
		Password: cfg.Database.Password, DBName: cfg.Database.DBName, SSLMode: cfg.Database.SSLMode,
		SkipInit: true, Logger: logger})
	if err != nil {
		return fmt.Errorf("open existing database: %w", err)
	}
	defer db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if !*apply {
		rows := make([]map[string]string, 0, len(ids))
		for _, id := range ids {
			var state, reason, conversationID, assessmentID string
			if err := db.QueryRowContext(ctx, `SELECT state,reason,conversation_id,assessment_id FROM result_ingestion_jobs WHERE execution_id=?`, id).Scan(&state, &reason, &conversationID, &assessmentID); err != nil {
				return fmt.Errorf("inspect %s: %w", id, err)
			}
			rows = append(rows, map[string]string{"execution_id": id, "state": state, "reason": reason, "conversation_id": conversationID, "assessment_id": assessmentID})
		}
		return encoder.Encode(map[string]interface{}{"dry_run": true, "selected_count": len(ids), "jobs": rows})
	}
	reports, replayErr := app.ReplayResultIngestions(ctx, db, &cfg, logger, ids)
	if err := encoder.Encode(map[string]interface{}{"dry_run": false, "selected_count": len(ids), "jobs": reports}); err != nil {
		return err
	}
	return replayErr
}
