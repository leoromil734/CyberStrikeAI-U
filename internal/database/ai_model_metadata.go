package database

import (
	"fmt"
)

// initAIModelMetadata is idempotent on SQLite and PostgreSQL. Old findings are
// deliberately left unattributed: the latest conversation model is not history.
func (db *DB) initAIModelMetadata() error {
	for _, column := range []struct{ table, name string }{
		{"conversation_ai_channels", "ai_channel_name"},
		{"vulnerabilities", "ai_channel_id"},
		{"vulnerabilities", "ai_channel_name"},
		{"vulnerabilities", "ai_model"},
	} {
		if err := db.addColumnIfMissing(column.table, column.name, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT NOT NULL DEFAULT ''", column.table, column.name)); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ai_source ON vulnerabilities(ai_channel_id, ai_model)`); err != nil {
		return err
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ai_channel_probes (
		channel_id TEXT PRIMARY KEY,
		config_hash TEXT NOT NULL,
		result_json TEXT NOT NULL,
		tested_at DATETIME NOT NULL
	)`)
	return err
}
