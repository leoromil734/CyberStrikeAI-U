package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Directory discovery budgeted as a single run can still be worthless when the
// edge answers every path identically. A 900-second dirsearch sweep that spends
// its whole budget behind a uniform 403 returns no findings, no gap detail and
// no signal that the candidate set was never actually reachable.
//
// This probe runs before dispatch. It requests a few random paths that cannot
// exist, and if every one of them comes back as the same interception response,
// the run is stopped and reported as a blocked edge/WAF condition instead of a
// completed negative result.

const (
	discoveryProbeMaxPaths      = 3
	discoveryProbeTimeout       = 12 * time.Second
	discoveryProbeTotalBudget   = 40 * time.Second
	discoveryProbeBodySamples   = 3
	discoveryProbeMaxBodyBytes  = 32 * 1024
	discoveryProbeMinBodySample = 256
)

// discoveryProbePath is the random segment used for the throwaway requests. It
// is generated per run so a cached "not found" page cannot be mistaken for a
// live response, and it carries no meaning for the target.
func discoveryProbePath() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		// The name only needs to be unlikely, not secret.
		return fmt.Sprintf("__csai_probe_%d", time.Now().UnixNano())
	}
	return "__csai_probe_" + hex.EncodeToString(raw)
}

// discoveryProbeAttempt is a single random-path request and what came back.
type discoveryProbeAttempt struct {
	Path        string `json:"path"`
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int    `json:"bytes,omitempty"`
	Server      string `json:"server,omitempty"`
	BodySample  string `json:"-"`
	Error       string `json:"error,omitempty"`
	markers     []string
}

// discoveryProbeVerdict is the decision attached to the tool result. It is
// deliberately explicit about what was and was not established: this is a
// baseline observation, not proof that the target is protected or unprotected.
type discoveryProbeVerdict struct {
	Tool           string                  `json:"tool"`
	BaseURL        string                  `json:"base_url"`
	Probes         []discoveryProbeAttempt `json:"probes"`
	Decision       string                  `json:"decision"`
	Reason         string                  `json:"reason"`
	UniformStatus  int                     `json:"uniform_status,omitempty"`
	UniformBytes   int                     `json:"uniform_bytes,omitempty"`
	EdgeMarkers    []string                `json:"edge_markers,omitempty"`
	NotEstablished []string                `json:"not_established"`
	Guidance       string                  `json:"guidance,omitempty"`
	Retryable      bool                    `json:"retryable"`
}

func (v *discoveryProbeVerdict) message() string {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("目录发现基线探测结论: %s", v.Reason)
	}
	return string(body)
}

// dirsearchProbeTarget returns the origin to probe and the client to use.
//
// The probe goes to the same origin and the same proxy as the scan, because the
// interception being detected lives at that edge for that egress. Probing
// directly while the scan runs through a proxy would measure a different path.
func dirsearchProbeTarget(args map[string]interface{}) (string, *http.Client, bool) {
	raw, ok := args["url"].(string)
	if !ok {
		return "", nil, false
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil, false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return "", nil, false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", nil, false
	}
	client := &http.Client{
		Timeout: discoveryProbeTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// A probe must observe the answer for the path it asked about. A
			// redirect to a login or interstitial page is itself a finding, so it
			// is reported rather than followed.
			return http.ErrUseLastResponse
		},
	}
	if proxyRaw, ok := args["proxy"].(string); ok {
		if proxyURL, proxyErr := url.Parse(strings.TrimSpace(proxyRaw)); proxyErr == nil && proxyURL.Host != "" {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}
	return parsed.Scheme + "://" + parsed.Host, client, true
}

func discoveryProbeOnce(ctx context.Context, client *http.Client, base, path string) discoveryProbeAttempt {
	attempt := discoveryProbeAttempt{Path: "/" + path}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+path, nil)
	if err != nil {
		attempt.Error = "probe_request_invalid"
		return attempt
	}
	request.Header.Set("User-Agent", "CyberStrikeAI-discovery-baseline/1.0")
	request.Header.Set("Accept", "*/*")
	response, err := client.Do(request)
	if err != nil {
		attempt.Error = "probe_request_failed"
		return attempt
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, discoveryProbeMaxBodyBytes))
		_ = response.Body.Close()
	}()
	attempt.Status = response.StatusCode
	attempt.ContentType = strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	attempt.Server = strings.TrimSpace(response.Header.Get("Server"))
	if attempt.Server == "" {
		attempt.Server = strings.TrimSpace(response.Header.Get("Via"))
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, discoveryProbeMaxBodyBytes))
	if readErr != nil && len(body) == 0 {
		attempt.Error = "probe_body_unreadable"
		return attempt
	}
	attempt.Bytes = len(body)
	attempt.BodySample = string(body)
	attempt.markers = edgeInterceptionMarkers(response.Header)
	return attempt
}

// edgeInterceptionMarkers lists response-header values that identify an edge
// proxy or bot-mitigation layer. They are evidence that the answer came from an
// intermediary, not from the application's own 404 handler.
func edgeInterceptionMarkers(header http.Header) []string {
	markers := []string{}
	for _, candidate := range []struct{ name, marker string }{
		{"Server", "cloudflare"}, {"Server", "akamai"}, {"Server", "sucuri"},
		{"Server", "imperva"}, {"Server", "incapsula"}, {"Server", "awselb"},
		{"Server", "big-ip"}, {"Server", "barracuda"}, {"Server", "safedog"},
		{"Server", "yunsuo"}, {"Server", "wangzhan"}, {"X-Sucuri-ID", ""},
		{"CF-Ray", ""}, {"X-Akamai-Transformed", ""}, {"X-Iinfo", ""},
		{"X-CDN", ""}, {"X-Powered-By-ChinaCache", ""},
	} {
		value := strings.TrimSpace(header.Get(candidate.name))
		if value == "" {
			continue
		}
		if candidate.marker != "" && !strings.Contains(strings.ToLower(value), candidate.marker) {
			continue
		}
		markers = append(markers, candidate.name+": "+value)
	}
	// Vendor prefixes are matched on the canonical name, not on a fixed list: a
	// WAF exposes itself as X-WAF-*, X-CF-*, X-WZWS-* and similar, and the exact
	// suffix is not knowable in advance. Looking for a literal "X-WAF-" header key
	// would miss every real X-WAF-Event-ID, because net/http canonicalises the
	// name to X-Waf-Event-Id on the way in.
	const markerSuffixLimit = 8
	for name, values := range header {
		canonical := http.CanonicalHeaderKey(name)
		lower := strings.ToLower(canonical)
		prefixMatch := false
		for _, prefix := range []string{"x-waf", "x-cf-", "x-wzws", "x-barracuda", "x-sucuri"} {
			if strings.HasPrefix(lower, prefix) {
				prefixMatch = true
				break
			}
		}
		if !prefixMatch && !strings.Contains(lower, "challenge") && !strings.Contains(lower, "cf-chl") {
			continue
		}
		joined := strings.Join(values, ",")
		if len(joined) > markerSuffixLimit*32 {
			joined = joined[:markerSuffixLimit*32] + "…"
		}
		markers = append(markers, canonical+": "+joined)
	}
	markers = sortStringsUnique(markers)
	return markers
}

func sortStringsUnique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	sort.Strings(values)
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// uniformInterceptionStatus reports whether a status code is a blanket denial
// rather than a per-path answer. 401/403/406/429/503 are what a WAF, an edge
// rule or a global rate limiter returns for a path it never routed.
func uniformInterceptionStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotAcceptable,
		http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	}
	return false
}

// evaluateDiscoveryBaseline decides whether the probe justifies stopping.
//
// The rule is deliberately narrow: every probe must have answered, all answers
// must share one interception status, and their bodies must be equivalent. A
// single differing answer, a mix of statuses, or any successful 404 with the
// application's own page means the scan should run normally — the point is to
// catch a uniform block, never to skip a scan that might find real paths.
func evaluateDiscoveryBaseline(base string, attempts []discoveryProbeAttempt, markers []string, elapsed time.Duration) *discoveryProbeVerdict {
	verdict := &discoveryProbeVerdict{
		Tool: "dirsearch", BaseURL: base, Probes: attempts, Decision: "proceed",
		NotEstablished: []string{
			"本探测只对少量随机不存在路径建立基线，不代表目标全部路径都不可达",
			"未完成候选集扫描，不能据此写出 covered 或“无目录/文件”负结果",
			"基线被拦截时不得改用统一页面批量否定真实接口",
		},
	}
	answered := make([]discoveryProbeAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.Error != "" {
			verdict.Decision = "abort"
			verdict.Reason = "探测请求本身失败，未建立基线: " + attempt.Error
			verdict.Guidance = "先确认目标可达与代理可用（proxy_healthcheck），再重跑目录发现；本次不消耗 900 秒扫描预算。"
			verdict.Retryable = true
			return verdict
		}
		answered = append(answered, attempt)
	}
	if len(answered) == 0 {
		verdict.Decision = "abort"
		verdict.Reason = "没有可用的基线响应"
		verdict.Retryable = true
		return verdict
	}

	status := answered[0].Status
	uniform := true
	for _, attempt := range answered {
		if attempt.Status != status {
			uniform = false
			break
		}
	}
	if !uniform {
		verdict.Reason = fmt.Sprintf("基线响应状态不一致（%s），判定为按路径响应，按常规扫描继续",
			probeStatusSummary(answered))
		verdict.Guidance = "请用实测差异设置 exclude_sizes/exclude_text/exclude_regex，不要猜测过滤值。"
		return verdict
	}
	verdict.UniformStatus = status
	verdict.UniformBytes = answered[0].Bytes

	if !uniformInterceptionStatus(status) {
		if status == http.StatusNotFound {
			verdict.Reason = "基线为应用自身的 404，未发现统一拦截；按常规扫描继续"
		} else {
			verdict.Reason = fmt.Sprintf("基线状态 %d 非统一拦截特征；按常规扫描继续", status)
		}
		return verdict
	}

	bodiesEquivalent := true
	for _, attempt := range answered[1:] {
		if !probeBodiesEquivalent(answered[0], attempt) {
			bodiesEquivalent = false
			break
		}
	}
	if !bodiesEquivalent {
		verdict.Reason = fmt.Sprintf("状态统一为 %d，但响应体长度/类型不一致，可能存在按路径差异；按常规扫描继续", status)
		verdict.Guidance = "先人工确认一个随机路径的响应，再决定是否使用统一页过滤。"
		return verdict
	}

	verdict.EdgeMarkers = markers
	verdict.Decision = "abort"
	verdict.Reason = fmt.Sprintf("全部 %d 个随机不存在路径返回相同的 %d 响应（%d 字节），判定为 WAF/边缘统一拦截，停止本轮扫描",
		len(answered), status, answered[0].Bytes)
	verdict.Retryable = true
	verdict.Guidance = "本轮按 blocked 记录（原因=edge_uniform_interception），保留基线证据；改用小字典降速、换出口（proxy_rotate 换国家/session）或先解除边缘挑战后再重跑。不要跑满 900 秒换取 0 结果。"
	if len(markers) > 0 {
		verdict.Guidance += " 已识别边缘特征：" + strings.Join(markers, "; ") + "。"
	}
	if elapsed > 0 {
		verdict.Guidance += fmt.Sprintf(" 基线探测耗时 %s，未进入扫描阶段。", elapsed.Round(time.Millisecond))
	}
	return verdict
}

func probeStatusSummary(attempts []discoveryProbeAttempt) string {
	parts := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		parts = append(parts, fmt.Sprintf("%d", attempt.Status))
	}
	return strings.Join(parts, ",")
}

// probeBodiesEquivalent compares two probe bodies on the properties that make a
// block page recognisable. Length plus a content prefix is enough: a WAF often
// embeds a per-request request id, so exact equality would miss real
// interceptions, while comparing only the length would match unrelated pages.
func probeBodiesEquivalent(left, right discoveryProbeAttempt) bool {
	if left.ContentType != right.ContentType {
		return false
	}
	if absInt(left.Bytes-right.Bytes) > 64 {
		return false
	}
	limit := len(left.BodySample)
	if len(right.BodySample) < limit {
		limit = len(right.BodySample)
	}
	if limit > discoveryProbeMinBodySample {
		limit = discoveryProbeMinBodySample
	}
	if limit == 0 {
		return left.Bytes == right.Bytes
	}
	// Ignore hex/date-like tokens, which are the parts of a block page that
	// legitimately differ per request.
	return normalizeProbeSample(left.BodySample[:limit]) == normalizeProbeSample(right.BodySample[:limit])
}

func normalizeProbeSample(sample string) string {
	var builder strings.Builder
	builder.Grow(len(sample))
	for _, r := range sample {
		switch {
		case r >= '0' && r <= '9':
			builder.WriteRune('#')
		case r >= 'a' && r <= 'f':
			// Hex digits inside ids are the usual per-request variation.
			builder.WriteRune('#')
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// probeDirsearchBaseline runs the pre-dispatch baseline and returns a verdict.
//
// It returns nil when there is nothing to judge (no usable URL, or the target is
// a bare placeholder), so a scan is never blocked by an inability to probe.
func (e *Executor) probeDirsearchBaseline(ctx context.Context, args map[string]interface{}) *discoveryProbeVerdict {
	base, client, ok := dirsearchProbeTarget(args)
	if !ok {
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, discoveryProbeTotalBudget)
	defer cancel()
	started := time.Now()
	attempts := make([]discoveryProbeAttempt, 0, discoveryProbeMaxPaths)
	for i := 0; i < discoveryProbeMaxPaths; i++ {
		if probeCtx.Err() != nil {
			break
		}
		attempts = append(attempts, discoveryProbeOnce(probeCtx, client, base, discoveryProbePath()))
	}
	var markers []string
	for _, attempt := range attempts {
		markers = append(markers, attempt.markers...)
	}
	return evaluateDiscoveryBaseline(base, attempts, sortStringsUnique(markers), time.Since(started))
}
