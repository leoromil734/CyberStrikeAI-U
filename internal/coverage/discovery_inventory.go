package coverage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
)

// DiscoveryMember references an independently parsed original, not a model's
// self-declared endpoint count. RawURL is never overwritten by the group key.
type DiscoveryMember struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	RawURL  string `json:"raw_url"`
	Method  string `json:"method"`
	Owner   string `json:"owner,omitempty"`
	ScopeID string `json:"scope_id,omitempty"`
}
type DiscoveryGroup struct {
	Key        string   `json:"key"`
	Kind       string   `json:"kind"`
	URL        string   `json:"example_original_url"`
	Method     string   `json:"method"`
	Members    int      `json:"members"`
	ExampleIDs []string `json:"example_ids"`
	Owner      string   `json:"owner,omitempty"`
	ScopeID    string   `json:"scope_id,omitempty"`
}

var routeQueryKeys = map[string]bool{"route": true, "action": true, "controller": true, "method": true, "service": true, "format": true, "op": true, "cmd": true, "request": true, "module": true, "function": true, "path": true, "page": true, "resource": true, "view": true, "handler": true, "endpoint": true}

// Group discovery work by exact origin/path/method and parameter names, retaining
// routing values. Ordinary parameter values remain in original inventory rows.
// Paths are not case-folded, decoded or rewritten to /:id templates.
func DiscoveryGroupKey(rawURL, method string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || u.Hostname() == "" || !oneOf(strings.ToLower(u.Scheme), "http", "https") {
		return "", fmt.Errorf("invalid discovery URL")
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("invalid query")
	}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	query := []interface{}{}
	for _, key := range keys {
		if routeQueryKeys[strings.ToLower(key)] {
			query = append(query, []interface{}{key, params[key]})
		} else {
			query = append(query, key)
		}
	}
	route := u.EscapedPath()
	if route == "" {
		route = "/"
	}
	identity, _ := json.Marshal([]interface{}{strings.ToLower(u.Scheme), net.JoinHostPort(strings.ToLower(u.Hostname()), port), method, route, query})
	sum := sha256.Sum256(identity)
	return fmt.Sprintf("discovery-%x", sum[:16]), nil
}

// discoveryBystanderSuffixes are public widget, captcha, analytics and social
// hosts extracted from page or bundle JavaScript. A brand assessment must not
// stall on a ledger row for each of them. The brand's own host is never listed.
var discoveryBystanderSuffixes = []string{
	"stripe.com",
	"braintreegateway.com",
	"braintree-api.com",
	"hcaptcha.com",
	"recaptcha.net",
	"gstatic.com",
	"googleapis.com",
	"google.com",
	"googletagmanager.com",
	"google-analytics.com",
	"doubleclick.net",
	"youtube.com",
	"ytimg.com",
	"facebook.com",
	"facebook.net",
	"fbcdn.net",
	"instagram.com",
	"pinterest.com",
	"pinimg.com",
	"twitter.com",
	"twimg.com",
	"tumblr.com",
	"linkedin.com",
	"licdn.com",
	"paystack.co",
	"payulatam.com",
	"cybersource.com",
	"authorize.net",
	"cardinalcommerce.com",
	"paypal.com",
	"paypalobjects.com",
	"afterpay.com",
	"cloudflareinsights.com",
	"jsdelivr.net",
	"unpkg.com",
	"cdnjs.cloudflare.com",
	"fontawesome.com",
	"bootstrapcdn.com",
	"jquery.com",
}

func DiscoveryBystanderHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, suffix := range discoveryBystanderSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func DiscoveryKind(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "endpoint"
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case ".js", ".mjs", ".cjs", ".map":
		return "js"
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webm":
		return "static"
	}
	// Downloads and permission-bearing document URLs remain endpoint work.
	return "endpoint"
}
func GroupDiscoveries(members []DiscoveryMember) []DiscoveryGroup {
	groups := map[string]*DiscoveryGroup{}
	for _, member := range members {
		if member.Kind != "endpoint" && member.Kind != "js" {
			continue
		}
		kind := DiscoveryKind(member.RawURL)
		if kind == "static" {
			continue
		}
		// Payment, captcha, analytics and social widget hosts are not the
		// brand's business surface. They stay in the original inventory, but
		// one missing ledger row per widget must not block delivery.
		if parsed, err := url.Parse(member.RawURL); err == nil && DiscoveryBystanderHost(parsed.Hostname()) {
			continue
		}
		key, err := DiscoveryGroupKey(member.RawURL, member.Method)
		if err != nil {
			continue
		}
		// Different owner/scope partitions retain separate work even when the
		// request identity is identical; a proof cannot silently cross either.
		partition, _ := json.Marshal([]string{kind, member.Owner, member.ScopeID, key})
		mapKey := string(partition)
		g := groups[mapKey]
		if g == nil {
			g = &DiscoveryGroup{Key: key, Kind: kind, URL: member.RawURL, Method: member.Method, Owner: member.Owner, ScopeID: member.ScopeID}
			groups[mapKey] = g
		}
		// JS records emitted alongside the same endpoint are not double counted.
		if member.Kind == "js" {
			continue
		}
		g.Members++
		if len(g.ExampleIDs) < 8 {
			g.ExampleIDs = append(g.ExampleIDs, member.ID)
		}
	}
	out := make([]DiscoveryGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Kind+out[i].Key+"\x00"+out[i].Owner+"\x00"+out[i].ScopeID < out[j].Kind+out[j].Key+"\x00"+out[j].Owner+"\x00"+out[j].ScopeID
	})
	return out
}

// CheckDiscoveryInventory is additive to the versioned ledger gate. A single
// self-consistent endpoint fact cannot cover unrelated discovered route groups.
func CheckDiscoveryInventory(facts []Fact, assessmentID string, groups []DiscoveryGroup) []string {
	mapped := map[string]bool{}
	for _, fact := range facts {
		kind := ledgerKind(fact.Key)
		if kind != "endpoint" && kind != "js" {
			continue
		}
		fields, err := parseBody(fact.Body)
		if err != nil || text(fields, "assessment_id") != assessmentID {
			continue
		}
		raw := text(fields, "endpoint_url")
		if kind == "js" {
			raw = text(fields, "url")
			if raw == "" {
				raw = text(fields, "resource_url")
			}
		}
		key, err := DiscoveryGroupKey(raw, text(fields, "method"))
		if err != nil {
			continue
		}
		if declared := text(fields, "inventory_group_key"); declared != "" && declared != key {
			continue
		}
		mapped[kind+":"+key] = true
	}
	missing := []string{}
	for _, group := range groups {
		if !mapped[group.Kind+":"+group.Key] {
			missing = append(missing, fmt.Sprintf("independent %s inventory group %s has no matching ledger disposition (original URL/method and routing parameters must match)", group.Kind, group.Key))
		}
	}
	return missing
}
