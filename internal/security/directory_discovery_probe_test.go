package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func probe(status int, contentType string, bytes int, sample string) discoveryProbeAttempt {
	return discoveryProbeAttempt{
		Path: "/__csai_probe_test", Status: status, ContentType: contentType,
		Bytes: bytes, BodySample: sample,
	}
}

func TestDiscoveryBaselineAbortsOnUniformForbiddenPage(t *testing.T) {
	page := "403 Forbidden: access denied by edge policy. Reference: 0a1b2c3d"
	attempts := []discoveryProbeAttempt{
		probe(http.StatusForbidden, "text/html", len(page), page),
		probe(http.StatusForbidden, "text/html", len(page), page),
		probe(http.StatusForbidden, "text/html", len(page), page),
	}
	verdict := evaluateDiscoveryBaseline("https://example.test", attempts, []string{"Server: cloudflare"}, 900*time.Millisecond)
	if verdict.Decision != "abort" {
		t.Fatalf("uniform interception must stop the scan, got %q", verdict.Decision)
	}
	if verdict.UniformStatus != http.StatusForbidden {
		t.Fatalf("uniform status not reported: %d", verdict.UniformStatus)
	}
	if len(verdict.NotEstablished) == 0 || len(verdict.EdgeMarkers) != 1 {
		t.Fatalf("verdict must keep limitations and edge evidence: %+v", verdict)
	}
	body := verdict.message()
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("verdict message must be JSON for the model: %v (%s)", err, body)
	}
	for _, required := range []string{"blocked", "900", "proxy_rotate"} {
		if !strings.Contains(verdict.Guidance, required) && !strings.Contains(verdict.Reason, required) {
			t.Errorf("verdict must explain %q: reason=%q guidance=%q", required, verdict.Reason, verdict.Guidance)
		}
	}
}

func TestDiscoveryBaselineProceedsOnApplicationNotFound(t *testing.T) {
	// A real application 404 is per-path: the scan must run normally.
	attempts := []discoveryProbeAttempt{
		probe(http.StatusNotFound, "text/html", 812, "<html>Not found</html>"),
		probe(http.StatusNotFound, "text/html", 812, "<html>Not found</html>"),
		probe(http.StatusNotFound, "text/html", 812, "<html>Not found</html>"),
	}
	verdict := evaluateDiscoveryBaseline("https://example.test", attempts, nil, 0)
	if verdict.Decision != "proceed" {
		t.Fatalf("application 404 must not be treated as interception: %+v", verdict)
	}
	if verdict.Retryable {
		t.Fatalf("proceed verdict must not request a retry: %+v", verdict)
	}
}

func TestDiscoveryBaselineProceedsWhenStatusesDiffer(t *testing.T) {
	attempts := []discoveryProbeAttempt{
		probe(http.StatusForbidden, "text/html", 512, "denied"),
		probe(http.StatusNotFound, "text/html", 300, "missing"),
		probe(http.StatusForbidden, "text/html", 512, "denied"),
	}
	verdict := evaluateDiscoveryBaseline("https://example.test", attempts, nil, 0)
	if verdict.Decision != "proceed" {
		t.Fatalf("mixed statuses are path-dependent answers, not a blanket block: %+v", verdict)
	}
	if !strings.Contains(verdict.Reason, "不一致") {
		t.Fatalf("reason must state why the block was not concluded: %q", verdict.Reason)
	}
}

func TestDiscoveryBaselineProceedsWhenBodiesDiffer(t *testing.T) {
	attempts := []discoveryProbeAttempt{
		probe(http.StatusForbidden, "text/html", 400, strings.Repeat("a", 300)),
		probe(http.StatusForbidden, "text/html", 900, strings.Repeat("b", 300)),
		probe(http.StatusForbidden, "text/html", 400, strings.Repeat("a", 300)),
	}
	verdict := evaluateDiscoveryBaseline("https://example.test", attempts, nil, 0)
	if verdict.Decision != "proceed" {
		t.Fatalf("differing bodies are not a uniform page: %+v", verdict)
	}
}

func TestDiscoveryBaselineAbortsOnProbeTransportFailure(t *testing.T) {
	attempts := []discoveryProbeAttempt{
		probe(http.StatusForbidden, "text/html", 400, "denied"),
		{Path: "/x", Error: "probe_request_failed"},
		probe(http.StatusForbidden, "text/html", 400, "denied"),
	}
	verdict := evaluateDiscoveryBaseline("https://example.test", attempts, nil, 0)
	if verdict.Decision != "abort" || !verdict.Retryable {
		t.Fatalf("a failed probe means no baseline exists: %+v", verdict)
	}
}

func TestProbeBodiesEquivalentToleratesPerRequestTokens(t *testing.T) {
	left := probe(http.StatusForbidden, "text/html", 300, "Request id: 9f8e7d6c5b4a that was denied")
	right := probe(http.StatusForbidden, "text/html", 300, "Request id: 1a2b3c4d5e6f that was denied")
	if !probeBodiesEquivalent(left, right) {
		t.Fatal("per-request hex tokens must not defeat interception detection")
	}
	different := probe(http.StatusForbidden, "text/html", 300, "completely other page content here")
	if probeBodiesEquivalent(left, different) {
		t.Fatal("unrelated bodies must not be treated as the same block page")
	}
	otherType := probe(http.StatusForbidden, "application/json", 300, "Request id: 9f8e7d6c5b4a that was denied")
	if probeBodiesEquivalent(left, otherType) {
		t.Fatal("content type differences must break equivalence")
	}
}

func TestEdgeInterceptionMarkersDetectKnownEdges(t *testing.T) {
	header := http.Header{}
	header.Set("Server", "cloudflare")
	header.Set("CF-Ray", "8f2b1c3d4e5f6a7b-SJC")
	header.Set("X-WAF-Event-ID", "abc123")
	markers := edgeInterceptionMarkers(header)
	joined := strings.ToLower(strings.Join(markers, " | "))
	// Case-insensitive on purpose: net/http canonicalises header names on the way
	// in, so "X-WAF-Event-ID" is stored as "X-Waf-Event-Id". The original spelling
	// is not recoverable at this point, and asserting it would make the test pass
	// or fail on the transport's normalisation rather than on detection.
	for _, want := range []string{"cloudflare", "cf-ray", "x-waf"} {
		if !strings.Contains(joined, want) {
			t.Errorf("marker %q missing from %q", want, joined)
		}
	}
	if len(edgeInterceptionMarkers(http.Header{})) != 0 {
		t.Fatal("an ordinary response must not report edge markers")
	}
}

func TestDirsearchProbeTargetRequiresUsableURL(t *testing.T) {
	for _, args := range []map[string]interface{}{
		{}, {"url": ""}, {"url": "   "}, {"url": "example.test/path"},
		{"url": "ftp://example.test"}, {"url": 42},
	} {
		if _, _, ok := dirsearchProbeTarget(args); ok {
			t.Errorf("unusable target accepted: %#v", args)
		}
	}
	base, client, ok := dirsearchProbeTarget(map[string]interface{}{"url": "https://example.test/app/?x=1"})
	if !ok || base != "https://example.test" || client == nil {
		t.Fatalf("usable target rejected: %q %v", base, ok)
	}
	// The probe must observe the answer for the requested path, not a redirect.
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("probe must not follow redirects: %v", err)
	}
}

func TestDirsearchProbeTargetUsesScanProxy(t *testing.T) {
	_, client, ok := dirsearchProbeTarget(map[string]interface{}{
		"url": "https://example.test", "proxy": "http://127.0.0.1:18080",
	})
	if !ok {
		t.Fatal("target rejected")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy == nil {
		t.Fatal("the probe must use the same egress as the scan")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/x", nil)
	proxied, err := transport.Proxy(request)
	if err != nil || proxied == nil || proxied.Host != "127.0.0.1:18080" {
		t.Fatalf("proxy not applied to probe: %v %v", proxied, err)
	}
}

// The probe is only useful if it actually distinguishes a uniform block page
// from a per-path answer end to end.
func TestDirsearchBaselineAgainstUniformEdge(t *testing.T) {
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied. Request id: deadbeefcafe"))
	}))
	defer blocked.Close()

	var attempts []discoveryProbeAttempt
	client := blocked.Client()
	for i := 0; i < discoveryProbeMaxPaths; i++ {
		attempts = append(attempts, discoveryProbeOnce(t.Context(), client, blocked.URL, discoveryProbePath()))
	}
	var markers []string
	for _, attempt := range attempts {
		markers = append(markers, attempt.markers...)
	}
	verdict := evaluateDiscoveryBaseline(blocked.URL, attempts, sortStringsUnique(markers), 0)
	if verdict.Decision != "abort" {
		t.Fatalf("uniform edge block must abort: %+v", verdict)
	}
	if len(verdict.EdgeMarkers) == 0 {
		t.Fatal("edge markers must be reported")
	}
}

func TestDirsearchBaselineAgainstPerPathServer(t *testing.T) {
	ordinary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found: " + r.URL.Path))
	}))
	defer ordinary.Close()

	var attempts []discoveryProbeAttempt
	client := ordinary.Client()
	for i := 0; i < discoveryProbeMaxPaths; i++ {
		attempts = append(attempts, discoveryProbeOnce(t.Context(), client, ordinary.URL, discoveryProbePath()))
	}
	verdict := evaluateDiscoveryBaseline(ordinary.URL, attempts, nil, 0)
	if verdict.Decision != "proceed" {
		t.Fatalf("an ordinary 404 must not stop the scan: %+v", verdict)
	}
}
