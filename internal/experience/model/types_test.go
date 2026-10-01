package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplicableRequiresKnownCompatibleConditions(t *testing.T) {
	conditions := Conditions{Product: "framework-a", Versions: []string{"1.2.3"}, Platform: "linux/amd64", Required: map[string]string{"auth": "anonymous"}, Excluded: map[string]string{"patched": "yes"}}
	matching := Search{Product: "FRAMEWORK-A", Version: "1.2.3", Platform: "linux/amd64", Facts: map[string]string{"auth": "anonymous", "patched": "no"}}
	if !Applicable(conditions, matching) {
		t.Fatal("compatible conditions did not match")
	}
	cases := []Search{
		{Product: "framework-b", Version: "1.2.3", Platform: matching.Platform, Facts: matching.Facts},
		{Product: matching.Product, Version: "1.2.4", Platform: matching.Platform, Facts: matching.Facts},
		{Product: matching.Product, Platform: matching.Platform, Facts: matching.Facts},
		{Product: matching.Product, Version: matching.Version, Facts: matching.Facts},
		{Product: matching.Product, Version: matching.Version, Platform: matching.Platform},
		{Product: matching.Product, Version: matching.Version, Platform: matching.Platform, Facts: map[string]string{"auth": "anonymous", "patched": "yes"}},
	}
	for i, query := range cases {
		if Applicable(conditions, query) {
			t.Errorf("case %d unexpectedly matched", i)
		}
	}
	tool := Conditions{ToolName: "scanner", ToolSchemaHash: "old-schema"}
	if Applicable(tool, Search{ToolName: "scanner", ToolSchemaHash: "new-schema"}) || Applicable(tool, Search{ToolName: "scanner"}) {
		t.Fatal("schema mismatch or unknown schema matched")
	}
}

func TestArgumentShapeNeverRetainsCustomerValues(t *testing.T) {
	args := map[string]interface{}{"command": "scanner https://customer.invalid/private --wrong -json", "token": "sensitive-token", "headers": map[string]interface{}{"X-Key": "private-key"}, "targets": []interface{}{"192.0.2.12", "customer.invalid"}, "count": 42, "enabled": true}
	b, err := json.Marshal(ArgumentShape(args))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"customer.invalid", "192.0.2.12", "sensitive-token", "private-key", "/private"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("private value retained: %s", secret)
		}
	}
	if !strings.Contains(string(b), "--wrong") || !strings.Contains(string(b), "-json") {
		t.Fatal("safe flags were not retained")
	}
	if !strings.Contains(string(b), "credential") {
		t.Fatal("sensitive fields were not marked")
	}
}

func TestErrorClassDoesNotLearnPermissionOrTransientErrors(t *testing.T) {
	for _, text := range []string{"permission denied", "invalid argument: network timeout", "unauthorized JSON", "context canceled", "connection refused", "权限不足，参数错误", "file not found: results.json"} {
		if ErrorClass(text) != "" {
			t.Errorf("unsafe learning error: %s", text)
		}
	}
	for _, text := range []string{"unknown flag --json", "missing required argument", "invalid character in JSON", "参数格式错误"} {
		if ErrorClass(text) == "" {
			t.Errorf("argument error not classified: %s", text)
		}
	}
}

func TestNormalizeArtifactsAndVerifiedVersionAllowlist(t *testing.T) {
	base := Content{Kind: KindVulnerability, Title: "verified method", Summary: "parameterized procedure", Conditions: Conditions{Product: " Framework-A ", Versions: []string{"1.2.3"}}, Steps: []string{"verify {{target}}"}, Verification: "compare baseline and observed behavior", Artifacts: []Artifact{{Name: "method.py", Content: "print('validation')"}}}
	if err := Normalize(&base); err != nil {
		t.Fatal(err)
	}
	if base.Conditions.Product != "framework-a" || base.Artifacts[0].SHA256 != Hash([]byte(base.Artifacts[0].Content)) {
		t.Fatal("content was not normalized or hashed")
	}
	for _, version := range []string{"", "*", ">=1.2.3", "unknown", "latest"} {
		base.Conditions.Versions = []string{version}
		if Normalize(&base) == nil {
			t.Errorf("unknown or inferred version accepted: %q", version)
		}
	}
	base.Conditions.Versions = nil
	if Normalize(&base) == nil {
		t.Fatal("vulnerability method accepted unknown verified versions")
	}
	base.Kind = KindWorkflow
	base.Artifacts[0].Name = "../outside.py"
	if Normalize(&base) == nil {
		t.Fatal("artifact traversal allowed")
	}
}
