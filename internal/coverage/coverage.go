// Package coverage checks versioned assessment ledgers without trusting report prose.
// It does not infer authorization or test intent from natural-language keywords.
package coverage

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Fact is deliberately independent of database and model runtime types.
type Fact struct {
	Key  string
	Body string
}

type Report struct {
	Active       bool
	AssessmentID string
	Missing      []string
	Blocked      []string // evidenced limitations are distinct from unclosed gaps
	EvidenceRefs []string
	ValidFacts   int // validated ledger records for diagnostics, not evidence of execution/repair progress
}

var assessmentIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)

var phases = []string{"recon_sources", "asset_ranking", "frontend_api", "auth_workflows", "risk_matrix", "gap_review"}

// Check activates only for an explicit coverage requirement or a versioned
// comprehensive manifest. Legacy notes are not silently interpreted as a ledger.
func Check(facts []Fact, required bool) Report {
	r := Report{}
	var manifest map[string]any
	var manifestKey string
	for _, fact := range facts {
		if !strings.HasPrefix(fact.Key, "recon/assessment/") {
			continue
		}
		fields, err := parseBody(fact.Body)
		if err != nil || text(fields, "mode") != "comprehensive" {
			if required {
				detail := "mode must be comprehensive"
				if err != nil {
					detail = err.Error()
				}
				r.Missing = append(r.Missing, fact.Key+": invalid comprehensive manifest: "+detail)
			}
			continue
		}
		if manifest != nil {
			r.Active = true
			r.Missing = append(r.Missing, "multiple active assessment manifests; select one assessment_id")
			return r
		}
		manifest, manifestKey = fields, fact.Key
	}
	if manifest == nil {
		if required {
			r.Active = true
			r.Missing = append(r.Missing, "missing recon/assessment/<id> manifest (schema_version: 2, mode: comprehensive)")
		}
		return r
	}
	r.Active = true
	r.AssessmentID = text(manifest, "assessment_id")
	if number(manifest, "schema_version") != 2 || !assessmentIDPattern.MatchString(r.AssessmentID) || manifestKey != "recon/assessment/"+r.AssessmentID {
		r.Missing = append(r.Missing, manifestKey+": schema_version must be 2 and key must match assessment_id")
		return r
	}
	if !oneOf(text(manifest, "status"), "active", "completed") {
		r.Missing = append(r.Missing, manifestKey+": invalid assessment status")
	}
	scope := text(manifest, "scope_kind")
	if !oneOf(scope, "root-domain", "single-url", "ip", "asset-list") {
		r.Missing = append(r.Missing, manifestKey+": scope_kind must describe the authorized scope")
	}
	type entry struct {
		fact   Fact
		fields map[string]any
	}
	entries := make(map[string]entry)
	phaseEntries := make(map[string]entry)
	sources := make(map[string]bool)
	inventory := map[string]map[string]bool{"endpoint": {}, "js": {}, "risk": {}}
	trackInventory := func(key string) {
		if set, ok := inventory[ledgerKind(key)]; ok {
			set[key] = true
		}
	}
	for _, fact := range facts {
		kind := ledgerKind(fact.Key)
		if fact.Key == manifestKey || kind == "" || kind == "assessment" {
			continue
		}
		inNamespace := ledgerNamespaceID(fact.Key) == r.AssessmentID
		if inNamespace {
			// Count stored inventory independently of parse validity. Otherwise a
			// broken JS body falsely tells the model to reduce js_count by one.
			trackInventory(fact.Key)
		}
		fields, err := parseBody(fact.Body)
		if err != nil {
			if inNamespace {
				r.Missing = append(r.Missing, fact.Key+": invalid ledger body: "+err.Error())
			}
			continue
		}
		if text(fields, "assessment_id") != r.AssessmentID {
			if inNamespace {
				r.Missing = append(r.Missing, fact.Key+": assessment_id does not match its namespace")
			}
			continue
		}
		if id := ledgerNamespaceID(fact.Key); id != "" && id != r.AssessmentID {
			r.Missing = append(r.Missing, fact.Key+": assessment_id does not match its namespace")
			continue
		}
		trackInventory(fact.Key) // compatible legacy keys with an explicit assessment_id
		if _, duplicate := entries[fact.Key]; duplicate {
			r.Missing = append(r.Missing, fact.Key+": duplicate ledger key")
		}
		e := entry{fact, fields}
		entries[fact.Key] = e
		if text(fields, "status") == "blocked" || text(fields, "runtime_status") == "blocked" {
			detail := text(fields, "blockers")
			if detail == "" {
				detail = text(fields, "reason")
			}
			if detail == "" {
				detail = text(fields, "error")
			}
			r.Blocked = append(r.Blocked, fact.Key+": "+detail)
		}
		switch {
		case strings.HasPrefix(fact.Key, "recon/phase/"):
			phase := fact.Key[strings.LastIndex(fact.Key, "/")+1:]
			if _, duplicate := phaseEntries[phase]; duplicate {
				r.Missing = append(r.Missing, fact.Key+": duplicate phase")
			}
			phaseEntries[phase] = e
			if !oneOf(text(fields, "status"), "passed", "blocked") || !meaningful(text(fields, "evidence")) {
				r.Missing = append(r.Missing, fact.Key+": phase needs terminal status and evidence")
			}
			if text(fields, "status") == "blocked" && !meaningful(text(fields, "blockers")) {
				r.Missing = append(r.Missing, fact.Key+": blocked phase needs original blockers and alternatives")
			}
		case strings.HasPrefix(fact.Key, "recon/source/"):
			status := text(fields, "status")
			valid := oneOf(status, "covered", "blocked", "not-applicable") && meaningful(text(fields, "evidence")) && text(fields, "tool") != "" && text(fields, "target") != ""
			for _, key := range []string{"raw", "unique", "incremental"} {
				valid = valid && number(fields, key) >= 0
			}
			valid = valid && number(fields, "unique") <= number(fields, "raw") && number(fields, "incremental") <= number(fields, "unique")
			if status == "blocked" {
				valid = valid && meaningful(text(fields, "error")) && hasAlternatives(fields)
			}
			if status == "not-applicable" {
				valid = valid && meaningful(text(fields, "reason"))
			}
			if !valid {
				diagnostic := ""
				if err := ValidateLedgerFact(fact.Key, fact.Body); err != nil {
					diagnostic = "; " + err.Error()
				}
				r.Missing = append(r.Missing, fact.Key+": source needs valid counts, evidence and blocker/alternative details"+diagnostic)
			}
			if valid && status != "not-applicable" {
				sources[text(fields, "tool")] = true
			}
		case strings.HasPrefix(fact.Key, "recon/js/"):
			if !oneOf(text(fields, "status"), "expanded", "blocked") || !meaningful(text(fields, "evidence")) {
				r.Missing = append(r.Missing, fact.Key+": JS resource is not expanded or evidenced blocked")
			}
			if text(fields, "status") == "blocked" && !meaningful(text(fields, "blockers")) {
				r.Missing = append(r.Missing, fact.Key+": JS blocker details missing")
			}
		case strings.HasPrefix(fact.Key, "recon/risk/"):
			status := text(fields, "status")
			if !oneOf(status, "covered", "negated", "blocked", "not-applicable") || !meaningful(text(fields, "evidence")) || text(fields, "endpoint_key") == "" || text(fields, "risk_family") == "" || text(fields, "identity") == "" {
				r.Missing = append(r.Missing, fact.Key+": risk unit needs terminal result, endpoint, identity, family and evidence")
			}
			if oneOf(status, "blocked", "not-applicable") && !meaningful(text(fields, "reason")) {
				r.Missing = append(r.Missing, fact.Key+": blocked/N/A requires a concrete reason")
			}
		}
	}
	for _, phase := range phases {
		if _, ok := phaseEntries[phase]; !ok {
			r.Missing = append(r.Missing, "missing recon/phase/"+r.AssessmentID+"/"+phase)
		}
	}
	if !sources["fofa_search"] {
		r.Missing = append(r.Missing, "missing evidenced recon/source for fofa_search (required initial reconnaissance source for every scope)")
	}
	if scope == "root-domain" {
		for _, tool := range []string{"subfinder", "oneforall", "dnsx"} {
			if !sources[tool] {
				r.Missing = append(r.Missing, "missing evidenced recon/source for "+tool)
			}
		}
	}
	if len(sources) == 0 {
		r.Missing = append(r.Missing, "missing evidenced inventory/baseline source")
	}
	for _, field := range []struct{ field, kind string }{
		{"endpoint_count", "endpoint"}, {"js_count", "js"}, {"risk_unit_count", "risk"},
	} {
		actual := len(inventory[field.kind])
		if declared := number(manifest, field.field); declared < 0 || declared != actual {
			r.Missing = append(r.Missing, fmt.Sprintf("%s: %s must equal inventory count %d", manifestKey, field.field, actual))
		}
	}
	for key, e := range entries {
		if strings.HasPrefix(key, "recon/endpoint/") {
			f := e.fields
			status := text(f, "runtime_status")
			if text(f, "host") == "" || text(f, "method") == "" || text(f, "path") == "" || !meaningful(text(f, "evidence")) {
				r.Missing = append(r.Missing, key+": endpoint baseline/identity evidence missing")
			}
			if status == "blocked" {
				if !meaningful(text(f, "blockers")) {
					r.Missing = append(r.Missing, key+": blocked endpoint needs concrete blockers")
				}
				continue
			}
			if !oneOf(status, "risk-mapped", "verified", "negated") {
				r.Missing = append(r.Missing, key+": endpoint still needs baseline and risk mapping")
			}
			units := list(f, "risk_units")
			if len(units) == 0 {
				r.Missing = append(r.Missing, key+": missing applicable risk_units (excluded items may use evidenced N/A)")
			}
			for _, unit := range units {
				u, ok := entries[unit]
				if !ok || !strings.HasPrefix(unit, "recon/risk/") || text(u.fields, "endpoint_key") != key {
					r.Missing = append(r.Missing, key+": missing or mismatched risk unit "+unit)
				}
			}
		}
		if strings.HasPrefix(key, "recon/risk/") {
			endpoint := text(e.fields, "endpoint_key")
			if _, ok := entries[endpoint]; !ok || !strings.HasPrefix(endpoint, "recon/endpoint/") {
				r.Missing = append(r.Missing, key+": referenced endpoint is absent from this assessment")
			}
		}
		r.EvidenceRefs = append(r.EvidenceRefs, "project_fact:"+key)
	}
	r.EvidenceRefs = append(r.EvidenceRefs, "project_fact:"+manifestKey)
	keys := []string{manifestKey}
	for key := range entries {
		keys = append(keys, key)
	}
	for _, key := range keys {
		valid := true
		for _, problem := range r.Missing {
			if strings.HasPrefix(problem, key+":") {
				valid = false
				break
			}
		}
		if valid {
			r.ValidFacts++
		}
	}
	sort.Strings(r.Missing)
	sort.Strings(r.Blocked)
	sort.Strings(r.EvidenceRefs)
	return r
}

func parseBody(body string) (map[string]any, error) {
	return ParseLedgerBody(body)
}
func text(f map[string]any, key string) string {
	v, ok := f[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}
func number(f map[string]any, key string) int {
	v, ok := f[key].(int)
	if !ok {
		return -1
	}
	return v
}
func list(f map[string]any, key string) []string {
	values, ok := f[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
func meaningful(s string) bool {
	return s != "" && !oneOf(strings.ToLower(s), "none", "null", "n/a", "[]", "无", "待补充", "todo") && !(strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">"))
}
func hasAlternatives(f map[string]any) bool {
	return len(list(f, "alt_tried")) > 0 || meaningful(text(f, "alt_tried"))
}
func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

// CanonicalEndpointFactKey opts new endpoint facts into collision-safe IDs when
// endpoint_url is supplied. Existing notes without that field retain their key.
func CanonicalEndpointFactKey(key, body string) (string, error) {
	if !strings.HasPrefix(key, "recon/endpoint/") {
		return key, nil
	}
	fields, err := parseBody(body)
	if err != nil {
		return key, nil
	} // Legacy free-form bodies stay compatible.
	rawURL := text(fields, "endpoint_url")
	if rawURL == "" {
		return key, nil
	}
	id := text(fields, "assessment_id")
	if !assessmentIDPattern.MatchString(id) {
		return "", fmt.Errorf("endpoint_url requires a valid assessment_id (1-48 lowercase slug characters)")
	}
	slug, err := EndpointKey(rawURL, text(fields, "method"))
	if declared := text(fields, "inventory_group_key"); declared != "" {
		group, groupErr := DiscoveryGroupKey(rawURL, text(fields, "method"))
		if groupErr != nil || declared != group {
			return "", fmt.Errorf("inventory_group_key must match original endpoint URL/method/routing values")
		}
		slug = group
	}
	if err != nil {
		return "", err
	}
	return "recon/endpoint/" + id + "/" + slug, nil
}

// LedgerStatus reads an actual status field for recovery/index prioritization.
// Invalid bodies return empty rather than inferring status from prose keywords.
func LedgerStatus(body string) string {
	fields, err := parseBody(body)
	if err != nil {
		return ""
	}
	if state := text(fields, "runtime_status"); state != "" {
		return state
	}
	return text(fields, "status")
}

// EndpointKey keeps case-sensitive paths and origin boundaries in the hash.
// Default ports normalize, query values and fragments are intentionally not IDs.
func EndpointKey(rawURL, method string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || !oneOf(strings.ToLower(u.Scheme), "http", "https") || u.User != nil {
		return "", fmt.Errorf("endpoint must be an HTTP(S) URL without userinfo")
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return "", fmt.Errorf("HTTP method is required")
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	identity := strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port) + "\n" + method + "\n" + path
	hash := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%s-%x", strings.ToLower(method), hash[:16]), nil
}
