package projectprompt

import (
	"strings"
	"testing"
)

func TestReconTemplatesIncludeRoundIdentityAndSourceEvidence(t *testing.T) {
	for _, key := range []string{"recon/source/run-a/subfinder/example", "recon/endpoint/run-a/main", "recon/phase/run-a/recon_sources"} {
		if template := ReconFactBodyTemplate(key); !strings.Contains(template, "assessment_id:") {
			t.Fatalf("versioned template omits assessment identity: key=%s template=%s", key, template)
		}
	}
	source := ReconFactBodyTemplate("recon/source/run-a/subfinder/example")
	for _, required := range []string{"raw_output", "真实整数", "evidence:", "active"} {
		if !strings.Contains(source, required) {
			t.Errorf("source template omits %q: %s", required, source)
		}
	}
}

func TestIsSparseReconFactBody(t *testing.T) {
	key := "recon/source/subfinder/example.com"
	if !IsSparseReconFactBody("recon", key, "") {
		t.Error("empty recon source body should be sparse")
	}
	if !IsSparseReconFactBody("recon", key, "status: covered\nraw: 10") {
		t.Error("partial recon source body should be sparse")
	}
	full := "status: covered\nraw: 10\nunique: 8\nincremental: 8\nerror: none\nalt_tried: []\ntool: subfinder\ntarget: example.com"
	if IsSparseReconFactBody("recon", key, full) {
		t.Error("full recon source body should not be sparse")
	}
	epKey := "recon/endpoint/api-example/get_api-v1-users"
	if !IsSparseReconFactBody("", epKey, "path: /api/v1/users") {
		t.Error("partial endpoint body should be sparse")
	}
	epFull := "host: api.example.com\nmethod: GET\npath: /api/v1/users\nparams: none\nauth_hint: anonymous\nsource_js: /app.js\nruntime_status: extracted\nvalue_reason: user list"
	if IsSparseReconFactBody("", epKey, epFull) {
		t.Error("full endpoint body should not be sparse")
	}
	if IsSparseReconFactBody("target", "target/x", "") {
		t.Error("non-recon should not be sparse via recon rules")
	}
}
