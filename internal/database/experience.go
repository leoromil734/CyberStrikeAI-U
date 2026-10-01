package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	em "cyberstrike-ai/internal/experience/model"

	"github.com/google/uuid"
)

var ErrExperienceNotFound = errors.New("experience not found or inaccessible")
var ErrExperienceConflict = errors.New("experience revision changed")

type ExperienceAccess struct {
	UserID string
	Global bool
	// ProjectID must be authorized by the caller before constructing access.
	ProjectID string
}

func (db *DB) initExperienceTables() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS experience_entries (
		 id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, origin_project_id TEXT NOT NULL DEFAULT '',
		 scope TEXT NOT NULL DEFAULT 'private', status TEXT NOT NULL DEFAULT 'candidate', revision INTEGER NOT NULL,
		 kind TEXT NOT NULL, product TEXT NOT NULL DEFAULT '', tool_name TEXT NOT NULL DEFAULT '',
		 content_json TEXT NOT NULL, content_hash TEXT NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
		 reviewed_by TEXT NOT NULL DEFAULT '', review_note TEXT NOT NULL DEFAULT '',
		 UNIQUE(owner_user_id, origin_project_id, content_hash))`,
		`CREATE TABLE IF NOT EXISTS experience_revisions (
		 entry_id TEXT NOT NULL REFERENCES experience_entries(id) ON DELETE CASCADE, revision INTEGER NOT NULL,
		 content_json TEXT NOT NULL, content_hash TEXT NOT NULL, created_by TEXT NOT NULL, created_at DATETIME NOT NULL,
		 PRIMARY KEY(entry_id, revision))`,
		`CREATE TABLE IF NOT EXISTS experience_evidence (
		 entry_id TEXT NOT NULL, revision INTEGER NOT NULL, execution_id TEXT NOT NULL, role TEXT NOT NULL,
		 PRIMARY KEY(entry_id, revision, execution_id),
		 FOREIGN KEY(entry_id, revision) REFERENCES experience_revisions(entry_id, revision) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS experience_execution_archives (
		 execution_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
		 project_id TEXT NOT NULL DEFAULT '', snapshot_json TEXT NOT NULL, content_hash TEXT NOT NULL,
		 archived_at DATETIME NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS experience_reviews (
		 id TEXT PRIMARY KEY, entry_id TEXT NOT NULL REFERENCES experience_entries(id) ON DELETE CASCADE,
		 revision INTEGER NOT NULL, reviewer_id TEXT NOT NULL, status TEXT NOT NULL, scope TEXT NOT NULL,
		 note TEXT NOT NULL, created_at DATETIME NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS experience_outcomes (
		 id TEXT PRIMARY KEY, entry_id TEXT NOT NULL, revision INTEGER NOT NULL, owner_user_id TEXT NOT NULL,
		 execution_id TEXT NOT NULL DEFAULT '', result TEXT NOT NULL, note TEXT NOT NULL, environment_json TEXT NOT NULL,
		 created_at DATETIME NOT NULL, UNIQUE(entry_id, revision, execution_id, result),
		 FOREIGN KEY(entry_id, revision) REFERENCES experience_revisions(entry_id, revision) ON DELETE CASCADE)`,
		`CREATE TABLE IF NOT EXISTS experience_execution_metadata (
		 execution_id TEXT PRIMARY KEY, tool_schema_hash TEXT NOT NULL, platform TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS experience_learning_events (
		 id TEXT PRIMARY KEY, execution_id TEXT NOT NULL UNIQUE, owner_user_id TEXT NOT NULL, conversation_id TEXT NOT NULL,
		 tool_name TEXT NOT NULL, tool_schema_hash TEXT NOT NULL, platform TEXT NOT NULL, status TEXT NOT NULL,
		 arguments_shape TEXT NOT NULL, error_class TEXT NOT NULL, started_at DATETIME NOT NULL, finished_at DATETIME NOT NULL,
		 state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '')`,
		`CREATE INDEX IF NOT EXISTS idx_experience_lookup ON experience_entries(status, kind, product, tool_name)`,
		`CREATE INDEX IF NOT EXISTS idx_experience_event_pending ON experience_learning_events(state, finished_at)`,
		`CREATE INDEX IF NOT EXISTS idx_experience_event_pair ON experience_learning_events(owner_user_id, conversation_id, tool_name, finished_at)`,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("experience schema: %w", err)
		}
	}
	return nil
}

func experienceAccessSQL(a ExperienceAccess) (string, []interface{}) {
	if strings.TrimSpace(a.UserID) == "" {
		return "1=0", nil
	}
	if a.Global {
		return "1=1", nil
	}
	q := "(owner_user_id = ? OR (scope = 'shared' AND status = 'verified')"
	args := []interface{}{a.UserID}
	if a.ProjectID != "" {
		q += " OR (scope = 'project' AND origin_project_id = ? AND status = 'verified')"
		args = append(args, a.ProjectID)
	}
	return q + ")", args
}

const experienceSelect = `SELECT id, owner_user_id, origin_project_id, scope, status, revision, content_json, content_hash, created_at, updated_at, reviewed_by, review_note,
 (SELECT COUNT(*) FROM experience_outcomes o WHERE o.entry_id = experience_entries.id AND o.revision = experience_entries.revision AND o.result = 'success'),
 (SELECT COUNT(*) FROM experience_outcomes o WHERE o.entry_id = experience_entries.id AND o.revision = experience_entries.revision AND o.result = 'failure') FROM experience_entries`

type experienceScanner interface{ Scan(...interface{}) error }

func scanExperience(row experienceScanner) (*em.Entry, error) {
	var e em.Entry
	var content string
	err := row.Scan(&e.ID, &e.OwnerUserID, &e.OriginProjectID, &e.Scope, &e.Status, &e.Revision, &content, &e.ContentHash, &e.CreatedAt, &e.UpdatedAt, &e.ReviewedBy, &e.ReviewNote, &e.Successes, &e.Failures)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(content), &e.Content); err != nil {
		return nil, err
	}
	return &e, nil
}

func (db *DB) GetExperience(id string, a ExperienceAccess) (*em.Entry, error) {
	where, args := experienceAccessSQL(a)
	args = append([]interface{}{id}, args...)
	e, err := scanExperience(db.QueryRow(experienceSelect+" WHERE id = ? AND "+where, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrExperienceNotFound
	}
	return e, err
}

func (db *DB) ListExperiences(a ExperienceAccess, status, kind, query string, limit, offset int) ([]*em.Entry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	where, args := experienceAccessSQL(a)
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}
	if kind != "" {
		where += " AND kind = ?"
		args = append(args, kind)
	}
	if query != "" {
		where += " AND LOWER(content_json) LIKE ?"
		args = append(args, "%"+strings.ToLower(query)+"%")
	}
	args = append(args, limit, offset)
	rows, err := db.Query(experienceSelect+" WHERE "+where+" ORDER BY updated_at DESC, id LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*em.Entry{}
	for rows.Next() {
		e, err := scanExperience(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateExperience deduplicates by owner/project/content, without widening an
// existing record's sharing scope or overwriting its review decision.
func (db *DB) CreateExperience(owner string, p em.Proposal) (*em.Entry, error) {
	if strings.TrimSpace(owner) == "" {
		return nil, fmt.Errorf("owner required")
	}
	if err := em.Normalize(&p.Content); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	id, err := createExperienceTx(tx, owner, p)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetExperience(id, ExperienceAccess{UserID: owner})
}

func createExperienceTx(tx *Tx, owner string, p em.Proposal) (string, error) {
	now := time.Now().UTC()
	id := uuid.NewString()
	content, err := json.Marshal(p.Content)
	if err != nil {
		return "", err
	}
	hash := em.ContentHash(p.Content)
	_, err = tx.Exec(`INSERT INTO experience_entries (id, owner_user_id, origin_project_id, revision, kind, product, tool_name, content_json, content_hash, created_at, updated_at)
	 VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(owner_user_id, origin_project_id, content_hash) DO NOTHING`, id, owner, p.OriginProjectID, p.Content.Kind, p.Content.Conditions.Product, p.Content.Conditions.ToolName, string(content), hash, now, now)
	if err != nil {
		return "", err
	}
	var revision int
	if err := tx.QueryRow(`SELECT id, revision FROM experience_entries WHERE owner_user_id = ? AND origin_project_id = ? AND content_hash = ?`, owner, p.OriginProjectID, hash).Scan(&id, &revision); err != nil {
		return "", err
	}
	_, err = tx.Exec(`INSERT INTO experience_revisions (entry_id, revision, content_json, content_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(entry_id, revision) DO NOTHING`, id, revision, string(content), hash, owner, now)
	if err != nil {
		return "", err
	}
	for _, evidence := range p.Evidence {
		if err := archiveExperienceExecutionTx(tx, evidence.ExecutionID); err != nil {
			return "", err
		}
		_, err = tx.Exec(`INSERT INTO experience_evidence (entry_id, revision, execution_id, role) VALUES (?, ?, ?, ?) ON CONFLICT(entry_id, revision, execution_id) DO NOTHING`, id, revision, evidence.ExecutionID, evidence.Role)
		if err != nil {
			return "", err
		}
	}
	return id, nil
}

func (db *DB) ExperienceEvidence(id string, revision int) ([]em.Evidence, error) {
	rows, err := db.Query(`SELECT execution_id, role FROM experience_evidence WHERE entry_id = ? AND revision = ? ORDER BY execution_id`, id, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []em.Evidence{}
	for rows.Next() {
		var e em.Evidence
		if err := rows.Scan(&e.ExecutionID, &e.Role); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) ReviseExperience(id, actor string, revision int, p em.Proposal) (*em.Entry, error) {
	if err := em.Normalize(&p.Content); err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, _ := json.Marshal(p.Content)
	hash := em.ContentHash(p.Content)
	now := time.Now().UTC()
	res, err := tx.Exec(`UPDATE experience_entries SET revision = revision + 1, content_json = ?, content_hash = ?, kind = ?, product = ?, tool_name = ?, status = 'candidate', scope = 'private', reviewed_by = '', review_note = '', updated_at = ? WHERE id = ? AND revision = ?`, string(b), hash, p.Content.Kind, p.Content.Conditions.Product, p.Content.Conditions.ToolName, now, id, revision)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrExperienceConflict
	}
	_, err = tx.Exec(`INSERT INTO experience_revisions (entry_id, revision, content_json, content_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`, id, revision+1, string(b), hash, actor, now)
	if err != nil {
		return nil, err
	}
	for _, e := range p.Evidence {
		if err := archiveExperienceExecutionTx(tx, e.ExecutionID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO experience_evidence (entry_id, revision, execution_id, role) VALUES (?, ?, ?, ?) ON CONFLICT(entry_id, revision, execution_id) DO NOTHING`, id, revision+1, e.ExecutionID, e.Role); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetExperience(id, ExperienceAccess{UserID: actor, Global: true})
}

func (db *DB) ReviewExperience(id, reviewer string, r em.Review) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE experience_entries SET status = ?, scope = ?, reviewed_by = ?, review_note = ?, updated_at = ? WHERE id = ? AND revision = ?`, r.Status, r.Scope, reviewer, r.Note, time.Now().UTC(), id, r.Revision)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrExperienceConflict
	}
	if _, err := tx.Exec(`INSERT INTO experience_reviews (id, entry_id, revision, reviewer_id, status, scope, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, uuid.NewString(), id, r.Revision, reviewer, r.Status, r.Scope, r.Note, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) SaveExperienceOutcome(actor string, o em.Outcome) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if o.Result == "success" || o.Result == "failure" {
		if err := archiveExperienceExecutionTx(tx, o.ExecutionID); err != nil {
			return err
		}
	}
	b, err := json.Marshal(o.Environment)
	if err != nil {
		return err
	}
	res, err := tx.Exec(`INSERT INTO experience_outcomes (id, entry_id, revision, owner_user_id, execution_id, result, note, environment_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(entry_id, revision, execution_id, result) DO NOTHING`, o.ID, o.EntryID, o.Revision, actor, o.ExecutionID, o.Result, o.Note, string(b), time.Now().UTC())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 && o.Result == "failure" {
		// Only real, evidence-backed failures on the current revision affect publication.
		_, err = tx.Exec(`UPDATE experience_entries SET status = 'needs_review', updated_at = ? WHERE id = ? AND revision = ? AND status = 'verified' AND (SELECT COUNT(*) FROM experience_outcomes WHERE entry_id = ? AND revision = ? AND result = 'failure') >= 3`, time.Now().UTC(), o.EntryID, o.Revision, o.EntryID, o.Revision)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ExperienceIndependentSuccesses(id string, revision int) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(DISTINCT c.id) FROM experience_outcomes o
	 JOIN experience_execution_archives a ON a.execution_id = o.execution_id
	 JOIN conversations c ON c.id = a.conversation_id
	 WHERE o.entry_id = ? AND o.revision = ? AND o.result = 'success'`, id, revision).Scan(&count)
	return count, err
}

func (db *DB) ExperienceRevisionHistory(id string) ([]map[string]interface{}, error) {
	rows, err := db.Query(`SELECT revision, content_json, content_hash, created_by, created_at FROM experience_revisions WHERE entry_id = ? ORDER BY revision DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]interface{}{}
	for rows.Next() {
		var rev int
		var raw, hash, actor string
		var at time.Time
		if err := rows.Scan(&rev, &raw, &hash, &actor, &at); err != nil {
			return nil, err
		}
		var c em.Content
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return nil, err
		}
		result = append(result, map[string]interface{}{"revision": rev, "content": c, "content_hash": hash, "created_by": actor, "created_at": at})
	}
	return result, rows.Err()
}
