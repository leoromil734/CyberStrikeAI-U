package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/evidence"
	"github.com/google/uuid"
)

func fenceIngestionProjection(ctx context.Context, tx *Tx, e evidence.Execution, claim *ResultIngestionJob) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	if claim == nil { // Explicit artifact registration, already authorized by host.
		return nil
	}
	if !jobMatchesExecution(*claim, e) || claim.LeaseToken == "" {
		return evidence.ErrDenied
	}
	// A write reservation/row lock and token check in the SAME transaction as
	// the projection prevents an expired worker overwriting a newer attempt.
	res, err := tx.ExecContext(ctx, `UPDATE result_ingestion_jobs SET updated_at_ms=updated_at_ms WHERE `+ingestionLeaseWhere, ingestionLeaseArgs(*claim)...)
	return ingestionAffected(res, err, ErrResultIngestionLeaseLost)
}

// ImportResultIngestionAssets is deliberately narrower than general asset
// editing. Existing metadata/status/ownership is never overwritten by replay;
// observations have deterministic IDs and are committed with the project link.
func (db *DB) ImportResultIngestionAssets(ctx context.Context, e evidence.Execution, assets []*Asset, claim *ResultIngestionJob) error {
	if len(assets) > 500 {
		return evidence.ErrLimit
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fenceIngestionProjection(ctx, tx, e, claim); err != nil {
		return err
	}
	access := RBACListAccess{UserID: e.Owner, Scope: RBACScopeOwn}
	if err = checkAssetProjectAccess(tx, e.ProjectID, access); err != nil {
		return err
	}
	for _, input := range assets {
		if input == nil || input.ProjectID != e.ProjectID || input.Status != "inactive" || input.Observation == nil || input.Observation.ExecutionID != e.ID || input.Observation.ConversationID != e.ConversationID {
			return evidence.ErrDenied
		}
		a := *input
		normalizeAsset(&a)
		if err = validateAsset(&a); err != nil {
			return fmt.Errorf("invalid ingestion asset: %w", err)
		}
		now := time.Now().UTC()
		key := assetDedupKey(&a)
		tags, _ := json.Marshal(a.Tags)
		_, err = tx.ExecContext(ctx, assetInsertSQL, uuid.NewString(), key, nullIfEmpty(a.ProjectID), a.Host, a.IP, a.Port, a.Domain, a.Protocol, a.Title, a.Server,
			a.Country, a.Province, a.City, a.Source, a.SourceQuery, "inactive", string(tags),
			a.ResponsiblePerson, a.Department, a.BusinessSystem, a.Environment, a.Criticality, now, now, now, now, nullIfEmpty(e.Owner))
		if err != nil {
			return err
		}
		var id, owner string
		if err = tx.QueryRowContext(ctx, `SELECT id,COALESCE(owner_user_id,'') FROM assets WHERE dedup_key=?`+db.assetRowLock(), key).Scan(&id, &owner); err != nil {
			return err
		}
		// Unlike general import, do not acquire an ownerless historical asset.
		if owner != e.Owner {
			continue
		}
		if err = linkAssetProject(tx, id, e.ProjectID, now); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(strings.Join([]string{e.ID, e.ProjectID, e.ConversationID, e.Owner, id, a.IP, a.Source}, "\x00")))
		observationID := "ingestion-" + hex.EncodeToString(digest[:])
		// The NOT EXISTS also recognizes observations created by older pipeline
		// versions, before deterministic IDs were introduced.
		_, err = tx.ExecContext(ctx, `INSERT INTO asset_observations(id,asset_id,project_id,ip,source,source_query,observed_at,conversation_id,execution_id)
 SELECT ?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM asset_observations WHERE asset_id=? AND project_id=? AND ip=? AND source=? AND conversation_id=? AND execution_id=?)
 ON CONFLICT(id) DO NOTHING`, observationID, id, e.ProjectID, a.IP, a.Source, a.SourceQuery, e.FinishedAt.UTC(), e.ConversationID, e.ID,
			id, e.ProjectID, a.IP, a.Source, e.ConversationID, e.ID)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ImportResultIngestionCandidate is insert-only so a later replay cannot turn a
// rejected/validated candidate back into a tentative scanner match.
func (db *DB) ImportResultIngestionCandidate(ctx context.Context, e evidence.Execution, c *FindingCandidate, claim *ResultIngestionJob) error {
	if c == nil || c.ProjectID != e.ProjectID || c.ConversationID != e.ConversationID || c.AssessmentID != e.AssessmentID || c.Target == "" || c.Title == "" || c.Status != "tentative" || c.RiskFamily != "scanner_match" ||
		len(c.Target) > 2048 || len(c.Title) > 512 || len(c.Summary) > 4096 || len(c.AssessmentID) > 48 {
		return evidence.ErrDenied
	}
	h := sha256.Sum256([]byte(strings.Join([]string{c.ProjectID, c.ConversationID, c.AssessmentID, c.Target, c.RiskFamily, c.Title}, "\x00")))
	id := "candidate-" + hex.EncodeToString(h[:16])
	refs, _ := json.Marshal([]string{"execution:" + e.ID})
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fenceIngestionProjection(ctx, tx, e, claim); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO finding_candidates(id,project_id,conversation_id,assessment_id,target,title,risk_family,impact_class,status,summary,reason,evidence_refs_json,related_vulnerability_id,priority,updated_at)
 VALUES(?,?,?,?,?,?,?,'unknown','tentative',?,'',?,'',50,?) ON CONFLICT(id) DO NOTHING`, id, e.ProjectID, e.ConversationID, e.AssessmentID, c.Target, c.Title, c.RiskFamily, c.Summary, string(refs), time.Now())
	if err != nil {
		return err
	}
	return tx.Commit()
}
