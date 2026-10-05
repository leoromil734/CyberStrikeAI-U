package coverage

import (
	"cyberstrike-ai/internal/evidence"
	"testing"
)

func TestDiscoveryBindingNeverCoalescesForeignPartitions(t *testing.T) {
	members := []DiscoveryMember{
		{ID: "one", Kind: "endpoint", RawURL: "https://example.invalid/api", Method: "GET", Owner: "u", ScopeID: "s"},
		{ID: "two", Kind: "endpoint", RawURL: "https://example.invalid/api", Method: "GET", Owner: "other", ScopeID: "s"},
		{ID: "three", Kind: "endpoint", RawURL: "https://example.invalid/api", Method: "GET", Owner: "u", ScopeID: "old-scope"},
	}
	groups := GroupDiscoveries(members)
	if len(groups) != 3 {
		t.Fatalf("foreign partitions merged: %+v", groups)
	}
	facts := []Fact{{Key: "recon/endpoint/a/api", Body: "assessment_id: a\nendpoint_url: https://example.invalid/api\nmethod: GET"}}
	binding := OriginalBinding{Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "u"}, ScopeID: "s", AssessmentID: "a"}
	if missing := CheckBoundDiscoveryInventory(facts, "a", groups, binding); len(missing) != 2 {
		t.Fatalf("cross-scope/owner proof applied: %v", missing)
	}
	if missing := CheckBoundDiscoveryInventory(facts, "a", groups, OriginalBinding{}); len(missing) != 3 {
		t.Fatalf("missing binding manufactured progress: %v", missing)
	}
	if len(groups) != 3 || len(members) != 3 {
		t.Fatal("inventory denominator changed")
	}
}
