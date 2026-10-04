package database

import (
	"encoding/json"
	"testing"
	"time"

	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
)

func TestResultIngestionSnapshotJSONPreservesPrivateOwnerAndTimes(t *testing.T) {
	start := time.Date(2026, 10, 5, 1, 7, 47, 123456789, time.FixedZone("UTC+8", 8*3600))
	end := start.Add(time.Second + 987654*time.Nanosecond)
	original := &mcp.ToolExecution{ID: "execution", OwnerUserID: "owner", ConversationID: "conversation", ToolName: "subfinder", Status: "completed", StartTime: start, EndTime: &end}
	s := ResultIngestionSnapshot{Execution: evidence.Execution{ID: original.ID, Access: evidence.Access{Owner: original.OwnerUserID, ConversationID: original.ConversationID}, Tool: original.ToolName, Status: original.Status, StartedAt: start, FinishedAt: end}, Original: original, Projection: ResultIngestionProjection{Owner: "owner", ProjectWrite: true, ProjectScope: "own"}}
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(body, &fields); err != nil || string(fields["original_owner"]) != `"owner"` {
		t.Fatalf("private owner was not stored: %s %v", body, err)
	}
	for i := 0; i < 3; i++ {
		var decoded ResultIngestionSnapshot
		if err = json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Original == nil || decoded.Original.OwnerUserID != "owner" || decoded.Execution.Access != s.Execution.Access || decoded.Projection != s.Projection || !decoded.Original.StartTime.Equal(start) || decoded.Original.EndTime == nil || !decoded.Original.EndTime.Equal(end) || !decoded.Execution.StartedAt.Equal(start) || !decoded.Execution.FinishedAt.Equal(end) {
			t.Fatalf("snapshot round trip %d lost private binding: %+v", i, decoded)
		}
		body, err = json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Compatibility is confined to the private snapshot: public monitor JSON
	// continues to omit the owner, exactly as the API type requires.
	public, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var monitor mcp.ToolExecution
	if err = json.Unmarshal(public, &monitor); err != nil || monitor.OwnerUserID != "" {
		t.Fatalf("public encoding changed: %s %v", public, err)
	}
}

func TestResultIngestionSnapshotJSONLegacyOwnerAndExplicitMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, ownerJSON, want string
	}{
		{"legacy_omitted", "", "owner"},
		{"explicit_mismatch", `,"original_owner":"other-owner"`, "other-owner"},
		{"explicit_empty", `,"original_owner":""`, ""},
		{"explicit_null", `,"original_owner":null`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"execution":{"owner":"owner"},"original":{"id":"execution"},"projection":{}` + tc.ownerJSON + `}`)
			var s ResultIngestionSnapshot
			if err := json.Unmarshal(body, &s); err != nil {
				t.Fatal(err)
			}
			if s.Original == nil || s.Original.OwnerUserID != tc.want || s.Projection.Owner != "" || s.Projection.ProjectWrite || s.Projection.AssetWrite {
				t.Fatalf("owner mismatch hidden or legacy authorization fabricated: %+v", s)
			}
		})
	}
	var missing ResultIngestionSnapshot
	if err := json.Unmarshal([]byte(`{"execution":{"owner":"owner"},"original":null}`), &missing); err != nil || missing.Original != nil {
		t.Fatalf("missing original fabricated: %+v %v", missing, err)
	}
}
