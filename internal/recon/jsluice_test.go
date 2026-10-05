package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"cyberstrike-ai/internal/evidence"
)

func TestJSLuiceNativeAndAdapterStaticCandidates(t *testing.T) {
	for _, raw := range []string{
		`{"url":"/api/users/EXPR?route=detail","method":"POST","type":"fetch","filename":"local.js","queryParams":["route"]}`,
		`{"url":"https://api.example.test:8443/v1/a?operation=read","method":"GET","filename":"local.js"}`,
		`{"url":"../relative","type":"stringLiteral"}`,
		`{"url":"//api.example.test/v1/a","method":"GET"}`,
		`{"schema":"csai.jsluice.v1","mode":"urls","source_js":"https://app.example.test/js/app.js","source_sha256":"` + strings.Repeat("a", 64) + `","url":"/v2/EXPR","method":"PATCH"}`,
	} {
		got, err := Parse(context.Background(), "csai-jsluice", "jsonl", strings.NewReader(raw+"\n"), Limits{})
		if err != nil || got.State != evidence.Parsed || len(got.Records) != 1 {
			t.Fatalf("%s: %+v %v", raw, got, err)
		}
		r := got.Records[0]
		if r.Kind != Endpoint || !r.CandidateOnly || got.Stats.Hosts != 0 || got.Stats.Services != 0 || got.Stats.JS != 0 {
			t.Fatalf("static extraction became observed asset: %+v", got)
		}
		var original map[string]interface{}
		_ = json.Unmarshal([]byte(raw), &original)
		if r.RawURL != original["url"] {
			t.Fatalf("relative URL was resolved or changed: %+v", r)
		}
		if original["method"] == nil && r.Method != "UNKNOWN" {
			t.Fatal("invented GET method")
		}
	}
}

func TestJSLuiceSecretsStayTentativeAndNeverCopyValues(t *testing.T) {
	raw := `{"schema":"csai.jsluice.v1","mode":"secrets","source_js":"https://app.example.test/js/app.js","source_sha256":"` + strings.Repeat("a", 64) + `","kind":"testKey","severity":"critical","data":{"value":"MUST_NOT_LEAK"},"context":{"token":"MUST_NOT_LEAK"}}`
	got, err := Parse(context.Background(), "jsluice", "jsonl", strings.NewReader(raw), Limits{})
	if err != nil || got.State != evidence.Parsed || len(got.Records) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	r := got.Records[0]
	if r.Kind != Candidate || r.Severity != "tentative" || !r.CandidateOnly || r.TemplateID != "jsluice-secret:testKey" {
		t.Fatalf("promoted secret: %+v", r)
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "MUST_NOT_LEAK") {
		t.Fatal("secret copied into inventory")
	}
}

func TestJSLuiceMalformedSummaryAndLimits(t *testing.T) {
	for _, raw := range []string{
		`{"complete":true,"counts":{"exported":99}}`,
		`{"url":"javascript:alert(1)"}`,
		`{"schema":"csai.jsluice.v1","mode":"urls","source_js":"https://example.test/app.js","source_sha256":"bad","url":"/api"}`,
		`{"kind":"token","data":{"value":"secret"},"filename":"/tmp/app.js"}`,
		`{"url":"/api","method":"GET\nPOST"}`,
	} {
		got, err := Parse(context.Background(), "jsluice", "jsonl", strings.NewReader(raw), Limits{})
		if err != nil || got.State != evidence.Invalid || len(got.Records) != 0 {
			t.Fatalf("bad record accepted: %+v %v", got, err)
		}
	}
	got, err := Parse(context.Background(), "jsluice", "jsonl", strings.NewReader(strings.Repeat("{\"url\":\"/api\"}\n", 3)), Limits{MaxRecords: 1})
	if err != nil || !got.Partial || got.Reason != "record_limit" {
		t.Fatalf("limit: %+v %v", got, err)
	}
	got, err = Parse(context.Background(), "jsluice", "log", strings.NewReader("https://example.test"), Limits{})
	if err != nil || got.State != evidence.Unsupported || len(got.Records) != 0 {
		t.Fatal("log guessed as machine output")
	}
}
