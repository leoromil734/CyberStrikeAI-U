package skillpackage

import (
	"regexp"
	"strings"
	"testing"
)

func TestIntegrationNewRoutesKeepOneModeDomainAndVerification(t *testing.T) {
	root := bundledSkillsRoot(t)
	_, _, router := readBundledSkill(t, root, "pentest-agent-os")
	want := map[string]string{
		"framework": "framework-security-testing",
		"backend":   "managed-backend-security",
		"infra":     "infra-control-plane-testing",
		"retest":    "security-regression-testing",
	}
	pattern := regexp.MustCompile("`([a-z0-9-]+)`")
	seen := map[string]bool{}
	for _, line := range strings.Split(router, "\n") {
		cells := strings.Split(strings.TrimSpace(line), "|")
		if len(cells) != 5 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(cells[1]), "`")
		domain, ok := want[key]
		if !ok {
			continue
		}
		if seen[key] {
			t.Errorf("duplicate new route %q", key)
		}
		seen[key] = true
		var got []string
		for _, match := range pattern.FindAllStringSubmatch(cells[3], -1) {
			got = append(got, match[1])
		}
		expected := "pentest-scan-standard," + domain + ",pentest-verification"
		if strings.Join(got, ",") != expected {
			t.Errorf("%s route = %v, want one mode/domain/verification", key, got)
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("new minimal route %q missing", key)
		}
	}
}
