package database

import (
	"encoding/json"

	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
)

// ResultIngestionProjection is an upper bound on the two optional projection
// permissions, captured from the authenticated execution context. It is NOT an
// authorization grant: workers also resolve the owner's current RBAC permissions
// and resource access. An absent snapshot (legacy jobs) grants neither permission.
type ResultIngestionProjection struct {
	Owner        string `json:"owner,omitempty"`
	ProjectWrite bool   `json:"project_write,omitempty"`
	ProjectScope string `json:"project_scope,omitempty"`
	AssetWrite   bool   `json:"asset_write,omitempty"`
	AssetScope   string `json:"asset_scope,omitempty"`
}

type ResultIngestionSnapshot struct {
	Execution  evidence.Execution        `json:"execution"`
	Original   *mcp.ToolExecution        `json:"original"`
	Projection ResultIngestionProjection `json:"projection"`
}

// ToolExecution deliberately hides OwnerUserID from public monitor JSON. The
// private queue snapshot must preserve it independently of that API encoding.
func (s ResultIngestionSnapshot) MarshalJSON() ([]byte, error) {
	type snapshotJSON ResultIngestionSnapshot
	var owner *string
	if s.Original != nil {
		owner = &s.Original.OwnerUserID
	}
	return json.Marshal(struct {
		snapshotJSON
		OriginalOwner *string `json:"original_owner,omitempty"`
	}{snapshotJSON(s), owner})
}

func (s *ResultIngestionSnapshot) UnmarshalJSON(body []byte) error {
	type snapshotJSON ResultIngestionSnapshot
	var wire struct {
		snapshotJSON
		OriginalOwner json.RawMessage `json:"original_owner"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return err
	}
	*s = ResultIngestionSnapshot(wire.snapshotJSON)
	if s.Original != nil {
		// Earlier private snapshots omitted the monitor's hidden owner field.
		// Their Execution.Owner was validated against the original at creation.
		// Load still checks the stored hash, job/metadata binding and any monitor
		// row before returning this snapshot; this is not caller authority.
		s.Original.OwnerUserID = s.Execution.Owner
		if len(wire.OriginalOwner) != 0 {
			var owner string
			if err := json.Unmarshal(wire.OriginalOwner, &owner); err != nil {
				return err
			}
			s.Original.OwnerUserID = owner
		}
	}
	return nil
}
