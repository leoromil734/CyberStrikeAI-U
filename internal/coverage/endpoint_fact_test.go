package coverage

import "testing"

func TestCanonicalEndpointFactKeyIsOptInAndBounded(t *testing.T) {
	legacy := "recon/endpoint/old/get_api"
	if key, err := CanonicalEndpointFactKey(legacy, "host: example.com\npath: /api"); err != nil || key != legacy {
		t.Fatalf("legacy key changed: %s %v", key, err)
	}
	body := "assessment_id: run-a\nmethod: GET\nendpoint_url: https://example.com/A/b"
	key, err := CanonicalEndpointFactKey("recon/endpoint/run-a/readable", body)
	if err != nil {
		t.Fatal(err)
	}
	slug, _ := EndpointKey("https://example.com/A/b", "GET")
	if key != "recon/endpoint/run-a/"+slug || len(key) > 128 {
		t.Fatalf("bad canonical key: %s", key)
	}
	if unchanged, err := CanonicalEndpointFactKey("note/anything", body); err != nil || unchanged != "note/anything" {
		t.Fatal("non-endpoint fact rewritten")
	}
	for _, body := range []string{"assessment_id: ../../other\nmethod: GET\nendpoint_url: https://example.com/", "assessment_id: run-a\nendpoint_url: https://example.com/", "assessment_id: run-a\nmethod: GET\nendpoint_url: file:///tmp/private"} {
		if _, err := CanonicalEndpointFactKey(legacy, body); err == nil {
			t.Fatalf("invalid endpoint identity accepted: %s", body)
		}
	}
}

func TestLedgerStatusDoesNotInferFromSummaryText(t *testing.T) {
	if got := LedgerStatus("notes: status active evidence"); got != "" {
		t.Fatalf("status guessed: %s", got)
	}
	if got := LedgerStatus("status: active\nruntime_status: extracted"); got != "extracted" {
		t.Fatalf("wrong endpoint state: %s", got)
	}
	if got := LedgerStatus("invalid: ["); got != "" {
		t.Fatalf("invalid YAML produced state: %s", got)
	}
}
