package coverage

import (
	"encoding/json"
	"testing"
)

func TestDiscoveryInventoryCannotShrinkToOneRouteGroup(t *testing.T) {
	members := []DiscoveryMember{
		{ID: "one", Kind: "endpoint", RawURL: "https://example.invalid:8443/API?route=account&format=json&id=1", Method: "GET"},
		{ID: "two", Kind: "endpoint", RawURL: "https://example.invalid:8443/API?route=account&format=json&id=2", Method: "GET"},
		{ID: "three", Kind: "endpoint", RawURL: "https://example.invalid:8443/API?route=admin&format=json&id=2", Method: "GET"},
		{ID: "four", Kind: "endpoint", RawURL: "https://example.invalid:443/API?route=admin&format=json&id=2", Method: "GET"},
		{ID: "five", Kind: "endpoint", RawURL: "https://example.invalid:8443/api?route=account&format=json&id=1", Method: "GET"},
	}
	groups := GroupDiscoveries(members)
	if len(groups) != 4 {
		t.Fatalf("routing/case/port collapsed: %+v", groups)
	}
	body, _ := json.Marshal(map[string]interface{}{"assessment_id": "run-a", "endpoint_url": members[0].RawURL, "method": "GET"})
	missing := CheckDiscoveryInventory([]Fact{{Key: "recon/endpoint/run-a/one", Body: string(body)}}, "run-a", groups)
	if len(missing) != 3 {
		t.Fatalf("one ledger row hid original groups: %v", missing)
	}
	if members[1].RawURL != "https://example.invalid:8443/API?route=account&format=json&id=2" {
		t.Fatal("original changed")
	}
}
func TestDiscoveryStaticJSMapsAndDownloadsStayDistinct(t *testing.T) {
	for raw, want := range map[string]string{"https://e.invalid/app.js": "js", "https://e.invalid/app.js.map": "js", "https://e.invalid/logo.png": "static", "https://e.invalid/account/invoice.pdf?id=7": "endpoint", "https://e.invalid/export.zip": "endpoint"} {
		if got := DiscoveryKind(raw); got != want {
			t.Fatalf("%s=%s want %s", raw, got, want)
		}
	}
}
func TestDiscoveryEndpointFactKeysKeepRoutingGroups(t *testing.T) {
	first, _ := DiscoveryGroupKey("https://e.invalid/api?route=users", "GET")
	second, _ := DiscoveryGroupKey("https://e.invalid/api?route=admin", "GET")
	body := func(route, key string) string {
		v, _ := json.Marshal(map[string]interface{}{"assessment_id": "run-a", "endpoint_url": "https://e.invalid/api?route=" + route, "method": "GET", "inventory_group_key": key})
		return string(v)
	}
	k1, err := CanonicalEndpointFactKey("recon/endpoint/run-a/x", body("users", first))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := CanonicalEndpointFactKey("recon/endpoint/run-a/x", body("admin", second))
	if err != nil || k1 == k2 {
		t.Fatalf("group IDs collided: %s %s %v", k1, k2, err)
	}
	if _, err = CanonicalEndpointFactKey("recon/endpoint/run-a/x", body("admin", first)); err == nil {
		t.Fatal("false group binding accepted")
	}
}
