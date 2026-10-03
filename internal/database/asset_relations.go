package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mattn/go-sqlite3"
)

// AssetObservation is append-only evidence for a stable service entity. IP and
// source come from the incoming Asset; callers may optionally supply the time
// and execution references through Asset.Observation. These references are
// evidence, never an authorization grant.
type AssetObservation struct {
	ID             string    `json:"id,omitempty"`
	AssetID        string    `json:"asset_id,omitempty"`
	ProjectID      string    `json:"project_id,omitempty"`
	IP             string    `json:"ip"`
	Source         string    `json:"source"`
	SourceQuery    string    `json:"source_query"`
	ObservedAt     time.Time `json:"observed_at"`
	ConversationID string    `json:"conversation_id,omitempty"`
	ExecutionID    string    `json:"execution_id,omitempty"`
}

const assetProjectLinksDDL = `CREATE TABLE IF NOT EXISTS asset_project_links (
	asset_id TEXT NOT NULL,
	project_id TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (asset_id, project_id),
	FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
)`

const assetObservationsDDL = `CREATE TABLE IF NOT EXISTS asset_observations (
	id TEXT PRIMARY KEY,
	asset_id TEXT NOT NULL,
	project_id TEXT,
	ip TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT '',
	source_query TEXT NOT NULL DEFAULT '',
	observed_at DATETIME NOT NULL,
	conversation_id TEXT NOT NULL DEFAULT '',
	execution_id TEXT NOT NULL DEFAULT '',
	FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
	FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
)`

// initAssetRelationsTables must run after the legacy assets/projects schema
// (including asset scan-column migrations). It is transactional and restart
// safe, and neither changes legacy dedup keys nor creates RBAC assignments.
func (db *DB) initAssetRelationsTables() error {
	return db.withAssetTransaction(func(tx *Tx) error {
		for _, stmt := range []string{
			assetProjectLinksDDL,
			assetObservationsDDL,
			`CREATE INDEX IF NOT EXISTS idx_asset_project_links_project ON asset_project_links(project_id,asset_id)`,
			`CREATE INDEX IF NOT EXISTS idx_asset_observations_asset_time ON asset_observations(asset_id,observed_at,id)`,
			`CREATE INDEX IF NOT EXISTS idx_asset_observations_ip ON asset_observations(ip,asset_id)`,
			`CREATE INDEX IF NOT EXISTS idx_asset_observations_source ON asset_observations(source,asset_id)`,
			`INSERT INTO asset_project_links (asset_id,project_id,created_at)
			 SELECT a.id,a.project_id,a.created_at FROM assets a JOIN projects p ON p.id=a.project_id
			 WHERE COALESCE(a.project_id,'')<>''
			 ON CONFLICT (asset_id,project_id) DO NOTHING`,
			// Deterministic IDs and NOT EXISTS avoid manufacturing a fresh legacy
			// observation on every restart or for assets written by the new code.
			`INSERT INTO asset_observations (id,asset_id,project_id,ip,source,source_query,observed_at,conversation_id,execution_id)
			 SELECT 'legacy:' || a.id,a.id,p.id,a.ip,a.source,a.source_query,a.last_seen_at,'',''
			 FROM assets a LEFT JOIN projects p ON p.id=a.project_id
			 WHERE NOT EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=a.id)
			 ON CONFLICT (id) DO NOTHING`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("初始化资产关系失败: %w", err)
			}
		}
		return nil
	})
}

// InitAssetRelationsTables also supports tests and custom Open(SkipInit=true)
// callers outside this package. Normal startup should use the private method
// from initTables and propagate any migration error before serving requests.
func (db *DB) InitAssetRelationsTables() error { return db.initAssetRelationsTables() }

const assetTransactionAttempts = 6

// Retry the entire transaction, not a statement inside a failed PostgreSQL
// transaction. The deadline also bounds lock waits; validation/permission and
// uniqueness errors are not retried. In particular, a duplicate identity in
// an explicit UpdateAsset is a real conflict rather than a retryable failure.
func (db *DB) withAssetTransaction(fn func(*Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	for attempt := 0; attempt < assetTransactionAttempts; attempt++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		var tx *Tx
		tx, err = db.BeginTx(ctx, nil)
		if err == nil {
			err = fn(tx)
			if err == nil {
				err = tx.Commit()
			}
			_ = tx.Rollback()
		}
		if err == nil || !retryableAssetTransactionError(err) || attempt+1 == assetTransactionAttempts {
			return err
		}
		timer := time.NewTimer(time.Duration(1<<attempt) * 10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func retryableAssetTransactionError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001" || pgErr.Code == "40P01" // serialization failure/deadlock
	}
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
	}
	return false
}

func (db *DB) assetRowLock() string {
	if db.IsPostgres() {
		return " FOR UPDATE"
	}
	return ""
}

// Relations narrow project selection, but never extend appendAssetAccess.
// The legacy column remains a fallback so old rows keep their visibility.
func appendAssetProjectScope(query string, args []interface{}, projectID string) (string, []interface{}) {
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		query += ` AND (assets.project_id=? OR EXISTS (
			SELECT 1 FROM asset_project_links apl WHERE apl.asset_id=assets.id AND apl.project_id=?
		))`
		args = append(args, projectID, projectID)
	}
	return query, args
}

// GetAssetForProject enforces both the relationship and the existing asset
// RBAC boundary. Access to a newly linked project alone never grants access to
// another user's shared service entity.
func (db *DB) GetAssetForProject(id, projectID string, access RBACListAccess) (*Asset, error) {
	query, args := appendAssetProjectScope("SELECT "+assetSelectColumns+" FROM assets LEFT JOIN projects p ON p.id=assets.project_id WHERE assets.id=?", []interface{}{strings.TrimSpace(id)}, projectID)
	query, args = appendAssetAccess(query, args, access, "assets")
	return scanAsset(db.QueryRow(query, args...))
}

// checkAssetProjectAccess validates the destination inside the writing
// transaction. An empty user retains the established trusted-internal-call
// convention; authenticated callers need global scope, ownership or an
// existing explicit project assignment, never a new asset relationship.
func checkAssetProjectAccess(tx *Tx, projectID string, access RBACListAccess) error {
	if projectID = strings.TrimSpace(projectID); projectID == "" {
		return nil
	}
	query := `SELECT COUNT(*) FROM projects WHERE id=?`
	args := []interface{}{projectID}
	if access.UserID != "" && access.Scope != RBACScopeAll {
		query += ` AND (owner_user_id=? OR EXISTS (SELECT 1 FROM rbac_resource_assignments ra
			WHERE ra.user_id=? AND ra.resource_type='project' AND ra.resource_id=projects.id))`
		args = append(args, access.UserID, access.UserID)
	}
	var n int
	if err := tx.QueryRow(query, args...).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("项目不存在或无权绑定该项目")
	}
	return nil
}

func linkAssetProject(tx *Tx, assetID, projectID string, now time.Time) error {
	if projectID = strings.TrimSpace(projectID); projectID == "" {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO asset_project_links (asset_id,project_id,created_at) VALUES (?,?,?)
		ON CONFLICT (asset_id,project_id) DO NOTHING`, assetID, projectID, now)
	return err
}

func appendAssetObservation(tx *Tx, assetID string, a *Asset, now time.Time) error {
	observation := AssetObservation{ObservedAt: now}
	if a.Observation != nil {
		observation = *a.Observation
		if observation.ObservedAt.IsZero() {
			observation.ObservedAt = now
		}
	}
	_, err := tx.Exec(`INSERT INTO asset_observations (id,asset_id,project_id,ip,source,source_query,observed_at,conversation_id,execution_id)
		VALUES (?,?,?,?,?,?,?,?,?)`, uuid.NewString(), assetID, nullIfEmpty(a.ProjectID), a.IP, a.Source, a.SourceQuery,
		observation.ObservedAt.UTC(), strings.TrimSpace(observation.ConversationID), strings.TrimSpace(observation.ExecutionID))
	return err
}

// ListAssetObservations provides bounded, paginated evidence. The optional
// project scope restricts evidence to that project's observations, in addition
// to requiring membership and the usual asset authorization.
func (db *DB) ListAssetObservations(id string, limit, offset int, access RBACListAccess, projectScope ...string) ([]*AssetObservation, int, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	projectID := ""
	if len(projectScope) > 0 {
		projectID = strings.TrimSpace(projectScope[0])
	}
	// Fail closed for an inaccessible asset, even if it has no observations.
	query, args := appendAssetProjectScope("SELECT COUNT(*) FROM assets WHERE assets.id=?", []interface{}{strings.TrimSpace(id)}, projectID)
	query, args = appendAssetAccess(query, args, access, "assets")
	var accessible int
	if err := db.QueryRow(query, args...).Scan(&accessible); err != nil {
		return nil, 0, err
	}
	if accessible != 1 {
		return nil, 0, sql.ErrNoRows
	}
	where := " WHERE o.asset_id=?"
	args = []interface{}{strings.TrimSpace(id)}
	if projectID != "" {
		where += " AND o.project_id=?"
		args = append(args, projectID)
	}
	where, args = appendAssetProjectScope(where, args, projectID)
	where, args = appendAssetAccess(where, args, access, "assets")
	from := " FROM asset_observations o JOIN assets ON assets.id=o.asset_id"
	var total int
	if err := db.QueryRow("SELECT COUNT(*)"+from+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT o.id,o.asset_id,COALESCE(o.project_id,''),o.ip,o.source,o.source_query,o.observed_at,o.conversation_id,o.execution_id`+from+where+` ORDER BY o.observed_at DESC,o.id ASC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []*AssetObservation{}
	for rows.Next() {
		var o AssetObservation
		if err := rows.Scan(&o.ID, &o.AssetID, &o.ProjectID, &o.IP, &o.Source, &o.SourceQuery, &o.ObservedAt, &o.ConversationID, &o.ExecutionID); err != nil {
			return nil, 0, err
		}
		items = append(items, &o)
	}
	return items, total, rows.Err()
}

// Preserve every duplicate's project memberships and observations before
// deleting it. Neither the surviving owner nor its legacy primary project is
// changed by merging relations, and no RBAC assignments are synthesized.
func mergeAssetRelations(tx *Tx, primaryID, duplicateID string) error {
	if _, err := tx.Exec(`INSERT INTO asset_project_links (asset_id,project_id,created_at)
		SELECT ?,project_id,created_at FROM asset_project_links WHERE asset_id=?
		ON CONFLICT (asset_id,project_id) DO NOTHING`, primaryID, duplicateID); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE asset_observations SET asset_id=? WHERE asset_id=?`, primaryID, duplicateID)
	return err
}
