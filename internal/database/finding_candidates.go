package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type FindingCandidate struct {
	ID                     string    `json:"id"`
	ProjectID              string    `json:"projectId"`
	ConversationID         string    `json:"conversationId"`
	AssessmentID           string    `json:"assessmentId,omitempty"`
	Target                 string    `json:"target"`
	Title                  string    `json:"title"`
	RiskFamily             string    `json:"riskFamily"`
	ImpactClass            string    `json:"impactClass"`
	Status                 string    `json:"status"`
	Summary                string    `json:"summary"`
	Reason                 string    `json:"reason,omitempty"`
	EvidenceRefs           []string  `json:"evidenceRefs,omitempty"`
	RelatedVulnerabilityID string    `json:"relatedVulnerabilityId,omitempty"`
	Priority               int       `json:"priority"`
	UpdatedAt              time.Time `json:"updatedAt"`
}

func (db *DB) initFindingCandidatesTables() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS finding_candidates(
		id TEXT PRIMARY KEY, project_id TEXT NOT NULL, conversation_id TEXT NOT NULL, assessment_id TEXT NOT NULL DEFAULT '',
		target TEXT NOT NULL,title TEXT NOT NULL,risk_family TEXT NOT NULL,impact_class TEXT NOT NULL,status TEXT NOT NULL,
		summary TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',evidence_refs_json TEXT NOT NULL DEFAULT '[]',
		related_vulnerability_id TEXT NOT NULL DEFAULT '',priority INTEGER NOT NULL DEFAULT 50,updated_at DATETIME NOT NULL,
		FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
		FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_finding_candidates_project ON finding_candidates(project_id,status,priority)`)
	return err
}

func (db *DB) UpsertFindingCandidate(c *FindingCandidate) error {
	if c == nil || c.ProjectID == "" || c.ConversationID == "" || c.Target == "" || c.Title == "" || c.RiskFamily == "" {
		return fmt.Errorf("candidate requires project, conversation, target, title and risk_family")
	}
	if len(c.AssessmentID) > 48 || len(c.RiskFamily) > 128 || len(c.ImpactClass) > 64 || len(c.Target) > 2048 || len(c.Title) > 512 || len(c.Summary) > 4096 || len(c.Reason) > 2048 || len(c.EvidenceRefs) > 32 {
		return fmt.Errorf("candidate metadata exceeds limits; keep raw evidence in artifacts")
	}
	allowed := map[string]bool{"observed": true, "tentative": true, "waiting": true, "blocked": true, "rejected": true, "validated": true}
	if !allowed[c.Status] {
		return fmt.Errorf("invalid candidate status")
	}
	if (c.Status == "blocked" || c.Status == "rejected") && strings.TrimSpace(c.Reason) == "" {
		return fmt.Errorf("blocked/rejected candidate requires concrete reason")
	}
	if c.Status == "validated" {
		v, err := db.GetVulnerability(c.RelatedVulnerabilityID)
		if err != nil || v == nil || v.ProjectID != c.ProjectID {
			return fmt.Errorf("validated candidate requires an accessible formal finding in this project")
		}
	}
	// An assessment is part of the identity: no cross-scope/cache substitution.
	h := sha256.Sum256([]byte(strings.Join([]string{c.ProjectID, c.ConversationID, c.AssessmentID, c.Target, c.RiskFamily, c.Title}, "\x00")))
	c.ID = "candidate-" + hex.EncodeToString(h[:16])
	c.UpdatedAt = time.Now()
	refs, _ := json.Marshal(c.EvidenceRefs)
	_, err := db.Exec(`INSERT INTO finding_candidates(id,project_id,conversation_id,assessment_id,target,title,risk_family,impact_class,status,summary,reason,evidence_refs_json,related_vulnerability_id,priority,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,summary=excluded.summary,
		reason=excluded.reason,evidence_refs_json=excluded.evidence_refs_json,related_vulnerability_id=excluded.related_vulnerability_id,
		priority=excluded.priority,impact_class=excluded.impact_class,updated_at=excluded.updated_at`,
		c.ID, c.ProjectID, c.ConversationID, c.AssessmentID, c.Target, c.Title, c.RiskFamily, c.ImpactClass, c.Status, c.Summary, c.Reason, string(refs), c.RelatedVulnerabilityID, c.Priority, c.UpdatedAt)
	return err
}

func (db *DB) ListFindingCandidates(projectID, status string, limit int) ([]FindingCandidate, error) {
	return db.ListFindingCandidatesPage(projectID, status, limit, 0)
}
func (db *DB) ListFindingCandidatesPage(projectID, status string, limit, offset int) ([]FindingCandidate, error) {
	if offset < 0 || offset > 100000 {
		return nil, fmt.Errorf("invalid candidate offset")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `SELECT id,project_id,conversation_id,assessment_id,target,title,risk_family,impact_class,status,summary,reason,evidence_refs_json,related_vulnerability_id,priority,updated_at FROM finding_candidates WHERE project_id=?`
	args := []interface{}{projectID}
	if status != "" {
		query += ` AND status=?`
		args = append(args, status)
	}
	query += ` ORDER BY priority DESC,updated_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingCandidate{}
	for rows.Next() {
		c := FindingCandidate{}
		var refs string
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.ConversationID, &c.AssessmentID, &c.Target, &c.Title, &c.RiskFamily, &c.ImpactClass, &c.Status, &c.Summary, &c.Reason, &refs, &c.RelatedVulnerabilityID, &c.Priority, &c.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(refs), &c.EvidenceRefs)
		out = append(out, c)
	}
	return out, rows.Err()
}
