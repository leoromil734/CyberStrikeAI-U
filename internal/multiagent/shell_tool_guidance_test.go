package multiagent

import (
	"strings"
	"testing"
)

func TestInjectShellToolGuidance(t *testing.T) {
	got := injectShellToolGuidance("base", []string{"nmap"})
	if got != "base" {
		t.Fatalf("expected unchanged, got %q", got)
	}
	got = injectShellToolGuidance("base", []string{"exec", "nmap"})
	for _, required := range []string{"exec/execute", "base", "<persisted-output>", "tmp/reduction/", "必须用 read_file", "禁止 exec/execute 调用 cat"} {
		if !strings.Contains(got, required) {
			t.Fatalf("expected %q in shell guidance, got %q", required, got)
		}
	}
}
