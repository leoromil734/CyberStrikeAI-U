package database

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// TemporaryMailbox stores ownership and creation reservations, never passwords
// or API keys. Unique slots bound concurrent/retried creation to two per task.
type TemporaryMailbox struct {
	ID             string    `json:"mailbox_id"`
	ConversationID string    `json:"-"`
	Slot           string    `json:"slot"`
	ProviderID     string    `json:"-"`
	Address        string    `json:"address"`
	TargetURL      string    `json:"registration_target"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

func (db *DB) EnsureTemporaryMailboxSchema() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS temporary_mailboxes (
		id TEXT PRIMARY KEY,
		conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
		slot TEXT NOT NULL CHECK (slot IN ('primary','secondary')),
		provider_id TEXT NOT NULL DEFAULT '',
		address TEXT NOT NULL UNIQUE,
		target_url TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TIMESTAMP NOT NULL,
		UNIQUE(conversation_id,slot)
	)`)
	return err
}

func scanTemporaryMailbox(s interface{ Scan(...any) error }) (*TemporaryMailbox, error) {
	var v TemporaryMailbox
	err := s.Scan(&v.ID, &v.ConversationID, &v.Slot, &v.ProviderID, &v.Address, &v.TargetURL, &v.Status, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

const temporaryMailboxColumns = "id,conversation_id,slot,provider_id,address,target_url,status,created_at"

func (db *DB) ReserveTemporaryMailbox(ctx context.Context, v *TemporaryMailbox) (*TemporaryMailbox, bool, error) {
	if v == nil || v.ID == "" || v.ConversationID == "" || (v.Slot != "primary" && v.Slot != "secondary") || v.Address == "" || v.TargetURL == "" {
		return nil, false, errors.New("invalid temporary mailbox reservation")
	}
	v.CreatedAt = time.Now().UTC()
	r, err := db.ExecContext(ctx, `INSERT INTO temporary_mailboxes (id,conversation_id,slot,address,target_url,status,created_at) VALUES (?,?,?,?,?,'pending',?) ON CONFLICT(conversation_id,slot) DO NOTHING`, v.ID, v.ConversationID, v.Slot, v.Address, v.TargetURL, v.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	stored, err := db.TemporaryMailboxBySlot(ctx, v.ConversationID, v.Slot)
	return stored, n == 1, err
}
func (db *DB) TemporaryMailboxBySlot(ctx context.Context, conversationID, slot string) (*TemporaryMailbox, error) {
	return scanTemporaryMailbox(db.QueryRowContext(ctx, "SELECT "+temporaryMailboxColumns+" FROM temporary_mailboxes WHERE conversation_id=? AND slot=?", conversationID, slot))
}
func (db *DB) GetTemporaryMailbox(ctx context.Context, conversationID, id string) (*TemporaryMailbox, error) {
	return scanTemporaryMailbox(db.QueryRowContext(ctx, "SELECT "+temporaryMailboxColumns+" FROM temporary_mailboxes WHERE conversation_id=? AND id=?", conversationID, id))
}
func (db *DB) ListTemporaryMailboxes(ctx context.Context, conversationID string) ([]*TemporaryMailbox, error) {
	rows, err := db.QueryContext(ctx, "SELECT "+temporaryMailboxColumns+" FROM temporary_mailboxes WHERE conversation_id=? ORDER BY created_at,id", conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []*TemporaryMailbox{}
	for rows.Next() {
		v, err := scanTemporaryMailbox(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}
func (db *DB) ActivateTemporaryMailbox(ctx context.Context, conversationID, id, providerID string) error {
	if providerID == "" {
		return errors.New("missing provider mailbox id")
	}
	r, err := db.ExecContext(ctx, "UPDATE temporary_mailboxes SET provider_id=?,status='active' WHERE conversation_id=? AND id=? AND status='pending'", providerID, conversationID, id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}
func (db *DB) MarkTemporaryMailboxDeleted(ctx context.Context, conversationID, id string) error {
	_, err := db.ExecContext(ctx, "UPDATE temporary_mailboxes SET status='deleted' WHERE conversation_id=? AND id=?", conversationID, id)
	return err
}
