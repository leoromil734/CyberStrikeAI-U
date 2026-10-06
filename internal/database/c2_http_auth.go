package database

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// BindC2HTTPIdentity binds a new HTTP implant identity without permitting an
// existing session to be claimed by a client that only knows its UUID.
func (db *DB) BindC2HTTPIdentity(listenerID, implantUUID, token string) (bool, error) {
	if strings.TrimSpace(listenerID) == "" || strings.TrimSpace(implantUUID) == "" || len(token) < 32 || len(token) > 256 {
		return false, nil
	}
	hash := sha256.Sum256([]byte(token))
	encoded := hex.EncodeToString(hash[:])
	_, err := db.Exec(`INSERT INTO c2_http_session_auth(implant_uuid,listener_id,token_hash)
 SELECT ?,?,? WHERE NOT EXISTS(SELECT 1 FROM c2_sessions WHERE implant_uuid=?)
 ON CONFLICT(implant_uuid) DO NOTHING`, implantUUID, listenerID, encoded, implantUUID)
	if err != nil {
		return false, err
	}
	return db.VerifyC2HTTPIdentity(listenerID, implantUUID, token)
}

func (db *DB) VerifyC2HTTPIdentity(listenerID, implantUUID, token string) (bool, error) {
	if len(token) < 32 || len(token) > 256 {
		return false, nil
	}
	var owner, stored string
	err := db.QueryRow(`SELECT listener_id,token_hash FROM c2_http_session_auth WHERE implant_uuid=?`, implantUUID).Scan(&owner, &stored)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	hash := sha256.Sum256([]byte(token))
	encoded := hex.EncodeToString(hash[:])
	return owner == listenerID && subtle.ConstantTimeCompare([]byte(stored), []byte(encoded)) == 1, nil
}

// C2HTTPFileIdentities resolves downstream file IDs through task payloads.
func (db *DB) C2HTTPFileIdentities(listenerID, fileID string) ([]string, error) {
	// Decode the top-level field in Go so SQLite and the locally supported
	// PostgreSQL backend both reject malformed JSON and nested file_id lookalikes.
	rows, err := db.Query(`SELECT s.implant_uuid, COALESCE(t.payload_json, '{}')
 FROM c2_tasks t JOIN c2_sessions s ON s.id=t.session_id WHERE s.listener_id=?`, listenerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identities []string
	seen := make(map[string]bool)
	for rows.Next() {
		var identity, payloadJSON string
		if err := rows.Scan(&identity, &payloadJSON); err != nil {
			return nil, err
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal([]byte(payloadJSON), &payload) != nil {
			continue
		}
		var taskFileID string
		if json.Unmarshal(payload["file_id"], &taskFileID) != nil || taskFileID != fileID || seen[identity] {
			continue
		}
		seen[identity] = true
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}
