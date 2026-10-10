package database

import (
	"strings"
	"time"
)

// ActiveScratchSessionIDs returns the project and conversation identifiers that
// had activity after the cutoff.
//
// Scratch retention deletes a session directory wholesale, so it needs to know
// which sessions are still in play. The database is the right source: a session
// directory has no heartbeat of its own, while conversations.updated_at and
// projects.updated_at move whenever the session is used. Anything updated after
// the cutoff is protected even if the on-disk tree looks old, which is the case
// that matters — a resumed session must not find its downloaded artifacts and
// spilled tool output deleted out from under it.
//
// The result mixes both identifier kinds in one set because the helper that
// names scratch directories uses project_id when present and the conversation id
// otherwise, and the sweeper only sees the directory name.
func (db *DB) ActiveScratchSessionIDs(cutoff time.Time) (map[string]bool, error) {
	active := map[string]bool{}
	if db == nil {
		return active, nil
	}
	rows, err := db.Query(`SELECT id FROM conversations WHERE updated_at >= ?`, cutoff)
	if err != nil {
		return active, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return active, err
		}
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			active[trimmed] = true
		}
	}
	if err := rows.Err(); err != nil {
		return active, err
	}
	// Projects use a separate table with the same timestamp convention. Both
	// identifiers are needed because a scratch directory is named after the
	// project when the session belongs to one, and after the conversation
	// otherwise.
	projectRows, err := db.Query(`SELECT id FROM projects WHERE updated_at >= ?`, cutoff)
	if err != nil {
		// A missing projects table must not fail the sweep; conversations alone
		// still protect the common case.
		return active, nil
	}
	defer projectRows.Close()
	for projectRows.Next() {
		var id string
		if err := projectRows.Scan(&id); err != nil {
			return active, err
		}
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			active[trimmed] = true
		}
	}
	return active, projectRows.Err()
}
