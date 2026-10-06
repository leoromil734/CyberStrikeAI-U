package c2

import (
	"strings"
	"testing"
)

func TestCallbackHostValidation(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "2001:db8::1", "localhost", "example.com", "host.docker.internal", "example.com."} {
		if err := ValidateBeaconDialHost(host); err != nil {
			t.Errorf("valid %q: %v", host, err)
		}
	}
	for _, host := range []string{"", "bad host/abc", "https://example.com", "example.com:443", "999.1.1.1", "-bad.example", "bad_.example", "a..example", "x';echo test", "$(echo test)", "example.\ncom", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 254)} {
		if err := ValidateBeaconDialHost(host); err == nil {
			t.Errorf("invalid %q accepted", host)
		}
		for _, kind := range AllOnelinerKinds() {
			result, err := GenerateOneliner(OnelinerInput{Kind: kind, Host: host, Port: 8080, HTTPBaseURL: "http://example.com:8080", ImplantToken: "test-only-token"})
			if err == nil || result != "" {
				t.Errorf("%s generated output for invalid host %q", kind, host)
			}
		}
	}
}

func TestCurlTemplateCarriesIndependentSessionCredential(t *testing.T) {
	command, err := GenerateOneliner(OnelinerInput{Kind: OnelinerCurl, Host: "localhost", Port: 12345, HTTPBaseURL: "http://localhost:12345", ImplantToken: "test-only-token"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "-N32") || !strings.Contains(command, "X-Session-Token") || strings.Count(command, `-H "$SH"`) != 2 {
		t.Fatal("curl check-in or task poll lacks independent session authentication")
	}
}

func TestBuildBeaconRejectsInvalidHostBeforeTemplateOrCompiler(t *testing.T) {
	manager, _ := c2SecurityTestManager(t)
	builder := NewPayloadBuilder(manager, manager.logger, t.TempDir(), t.TempDir())
	for _, host := range []string{"https://example.com", "bad host/abc", "example.com:443"} {
		result, err := builder.BuildBeacon(PayloadBuilderInput{ListenerID: "listener", Host: host})
		if result != nil || err == nil || !strings.Contains(err.Error(), "callback") {
			t.Fatalf("invalid host must fail before reading templates or invoking compiler: %v", err)
		}
	}
}
