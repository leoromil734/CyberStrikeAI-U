package coverage

import "fmt"

// CheckBoundDiscoveryInventory preserves every original partition and its
// denominator. Old/foreign-owner or changed-scope rows are explicit unresolved
// work, never silently removed or disposed by another partition's proof.
// facts must already be filtered against verified originals by the finalizer.
func CheckBoundDiscoveryInventory(facts []Fact, assessmentID string, groups []DiscoveryGroup, binding OriginalBinding) []string {
	var eligible []DiscoveryGroup
	var missing []string
	for _, g := range groups {
		if binding.AssessmentID != assessmentID || binding.Owner == "" || binding.ScopeID == "" || g.Owner != binding.Owner || g.ScopeID != binding.ScopeID {
			missing = append(missing, fmt.Sprintf("independent %s inventory group %s has no matching ledger disposition (owner/scope proof binding missing or different; original retained)", g.Kind, g.Key))
			continue
		}
		eligible = append(eligible, g)
	}
	return append(missing, CheckDiscoveryInventory(facts, assessmentID, eligible)...)
}
