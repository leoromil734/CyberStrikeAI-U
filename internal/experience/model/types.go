// Package model defines transport-independent, evidence-backed experience records.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	KindToolRepair    = "tool_repair"
	KindVulnerability = "vulnerability_method"
	KindWorkflow      = "workflow"
	KindNegative      = "negative_result"
	StatusCandidate   = "candidate"
	StatusVerified    = "verified"
	StatusReview      = "needs_review"
	StatusDeprecated  = "deprecated"
	ScopePrivate      = "private"
	ScopeProject      = "project"
	ScopeShared       = "shared"
)

// Conditions deliberately use an exact verified-version allowlist. A single
// observation must never invent a wider version range. Unknown values fail closed.
type Conditions struct {
	Product        string            `json:"product,omitempty"`
	Versions       []string          `json:"versions,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolSchemaHash string            `json:"tool_schema_hash,omitempty"`
	Platform       string            `json:"platform,omitempty"`
	Required       map[string]string `json:"required,omitempty"`
	Excluded       map[string]string `json:"excluded,omitempty"`
}

type Content struct {
	Kind         string            `json:"kind"`
	Title        string            `json:"title"`
	Summary      string            `json:"summary"`
	Conditions   Conditions        `json:"conditions"`
	Steps        []string          `json:"steps"`
	Parameters   map[string]string `json:"parameters,omitempty"`
	Verification string            `json:"verification"`
	FailureNotes []string          `json:"failure_notes,omitempty"`
	Cleanup      string            `json:"cleanup,omitempty"`
	Sources      []string          `json:"sources,omitempty"`
	// Artifacts are inline, reviewed text, never arbitrary host file paths.
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

type Artifact struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}

type Entry struct {
	ID              string    `json:"id"`
	OwnerUserID     string    `json:"owner_user_id"`
	OriginProjectID string    `json:"origin_project_id,omitempty"`
	Scope           string    `json:"scope"`
	Status          string    `json:"status"`
	Revision        int       `json:"revision"`
	Content         Content   `json:"content"`
	ContentHash     string    `json:"content_hash"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ReviewedBy      string    `json:"reviewed_by,omitempty"`
	ReviewNote      string    `json:"review_note,omitempty"`
	Successes       int       `json:"successes"`
	Failures        int       `json:"failures"`
}

type Evidence struct {
	ExecutionID string `json:"execution_id"`
	Role        string `json:"role"` // failed | corrected | validation
}

type Detail struct {
	Entry    *Entry     `json:"entry"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

type Proposal struct {
	Content         Content    `json:"content"`
	Evidence        []Evidence `json:"evidence"`
	OriginProjectID string     `json:"origin_project_id,omitempty"`
}

type Search struct {
	Query          string            `json:"query"`
	Kind           string            `json:"kind,omitempty"`
	Product        string            `json:"product,omitempty"`
	Version        string            `json:"version,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolSchemaHash string            `json:"tool_schema_hash,omitempty"`
	Platform       string            `json:"platform,omitempty"`
	Facts          map[string]string `json:"facts,omitempty"`
	ProjectID      string            `json:"project_id,omitempty"`
	Limit          int               `json:"limit,omitempty"`
}

type Match struct {
	ID         string     `json:"id"`
	Revision   int        `json:"revision"`
	Kind       string     `json:"kind"`
	Title      string     `json:"title"`
	Summary    string     `json:"summary"`
	Conditions Conditions `json:"conditions"`
	Score      float64    `json:"score"`
}

type Review struct {
	Revision int    `json:"revision"`
	Status   string `json:"status"`
	Scope    string `json:"scope"`
	Note     string `json:"note"`
}

type Outcome struct {
	ID          string `json:"id"`
	EntryID     string `json:"entry_id"`
	Revision    int    `json:"revision"`
	ExecutionID string `json:"execution_id,omitempty"`
	Result      string `json:"result"` // success | failure | environment_mismatch | inconclusive
	Note        string `json:"note"`
	Environment Search `json:"environment"`
}

func Normalize(c *Content) error {
	c.Kind = strings.TrimSpace(c.Kind)
	switch c.Kind {
	case KindToolRepair, KindVulnerability, KindWorkflow, KindNegative:
	default:
		return fmt.Errorf("invalid experience kind")
	}
	c.Title = strings.TrimSpace(c.Title)
	c.Summary = strings.TrimSpace(c.Summary)
	if c.Title == "" || c.Summary == "" || len(c.Steps) == 0 || strings.TrimSpace(c.Verification) == "" {
		return fmt.Errorf("title, summary, steps and verification are required")
	}
	if len(c.Title) > 300 || len(c.Summary) > 4000 || len(c.Steps) > 50 || len(c.Artifacts) > 10 {
		return fmt.Errorf("experience content exceeds limits")
	}
	c.Conditions.Product = canonical(c.Conditions.Product)
	c.Conditions.ToolName = strings.TrimSpace(c.Conditions.ToolName)
	c.Conditions.Platform = canonical(c.Conditions.Platform)
	c.Conditions.ToolSchemaHash = strings.TrimSpace(c.Conditions.ToolSchemaHash)
	for i, v := range c.Conditions.Versions {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 100 || strings.ContainsAny(v, "*<>,|") || canonical(v) == "unknown" || canonical(v) == "latest" || canonical(v) == "n/a" || v == "未知" {
			return fmt.Errorf("versions must be explicit observed values, not unknown versions or inferred ranges")
		}
		c.Conditions.Versions[i] = v
	}
	sort.Strings(c.Conditions.Versions)
	if c.Kind == KindToolRepair && (c.Conditions.ToolName == "" || c.Conditions.ToolSchemaHash == "") {
		return fmt.Errorf("tool repair requires tool_name and tool_schema_hash")
	}
	if c.Kind == KindVulnerability && (c.Conditions.Product == "" || len(c.Conditions.Versions) == 0) {
		return fmt.Errorf("vulnerability method requires product and explicitly verified versions")
	}
	for _, step := range c.Steps {
		if strings.TrimSpace(step) == "" {
			return fmt.Errorf("empty step")
		}
	}
	seen := map[string]bool{}
	for i := range c.Artifacts {
		a := &c.Artifacts[i]
		if !artifactName.MatchString(a.Name) || seen[a.Name] || len(a.Content) > 128*1024 {
			return fmt.Errorf("invalid or duplicate artifact name or size")
		}
		seen[a.Name] = true
		a.SHA256 = Hash([]byte(a.Content))
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(b) > 256*1024 {
		return fmt.Errorf("experience exceeds 256 KiB")
	}
	return nil
}

var artifactName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$`)

func canonical(s string) string    { return strings.ToLower(strings.TrimSpace(s)) }
func Hash(b []byte) string         { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func ContentHash(c Content) string { b, _ := json.Marshal(c); return Hash(b) }

func Applicable(c Conditions, s Search) bool {
	if c.Product != "" && canonical(s.Product) != canonical(c.Product) {
		return false
	}
	if len(c.Versions) > 0 {
		found := false
		for _, v := range c.Versions {
			if strings.TrimSpace(s.Version) != "" && v == strings.TrimSpace(s.Version) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if c.ToolName != "" && c.ToolName != strings.TrimSpace(s.ToolName) {
		return false
	}
	if c.ToolSchemaHash != "" && c.ToolSchemaHash != strings.TrimSpace(s.ToolSchemaHash) {
		return false
	}
	if c.Platform != "" && canonical(s.Platform) != canonical(c.Platform) {
		return false
	}
	for key, value := range c.Required {
		if s.Facts[key] != value || value == "" {
			return false
		}
	}
	for key, value := range c.Excluded {
		actual, known := s.Facts[key]
		if !known || actual == "" || value == "" || actual == value {
			return false
		}
	}
	return true
}

// ArgumentShape preserves flags, booleans and types, but never target values,
// arbitrary command strings, credentials, headers, or customer response data.
func ArgumentShape(v any) any { return argumentShape(v, "") }

var flag = regexp.MustCompile(`^--?[a-zA-Z][a-zA-Z0-9_-]*$`)

func argumentShape(v any, key string) any {
	lower := strings.ToLower(key)
	for _, sensitive := range []string{"password", "secret", "token", "cookie", "authorization", "credential", "api_key", "apikey", "headers", "session"} {
		if strings.Contains(lower, sensitive) {
			return "{{credential}}"
		}
	}
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, value := range x {
			out[k] = argumentShape(value, k)
		}
		return out
	case []interface{}:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = argumentShape(value, key)
		}
		return out
	case string:
		if flag.MatchString(x) {
			return x
		}
		flags := []string{}
		for _, word := range strings.Fields(x) {
			if flag.MatchString(word) {
				flags = append(flags, word)
			}
		}
		if len(flags) > 0 {
			return map[string]interface{}{"value": "{{" + key + ":string}}", "flags": flags}
		}
		return "{{" + key + ":string}}"
	case bool:
		return x
	case nil:
		return nil
	default:
		return "{{" + key + ":number}}"
	}
}

// ErrorClass only accepts syntax/argument problems for automated learning.
// Permission, network, cancellation and timeout failures are not repair proof.
func ErrorClass(text string) string {
	s := strings.ToLower(text)
	for _, part := range []string{"permission", "unauthorized", "forbidden", "denied", "timeout", "timed out", "cancel", "network", "connection", "权限", "超时", "取消"} {
		if strings.Contains(s, part) {
			return ""
		}
	}
	for _, part := range []string{"unknown flag", "unrecognized argument", "unexpected argument", "invalid argument", "required argument", "missing required", "json parse", "parse json", "invalid json", "malformed json", "invalid character", "unexpected end of json", "unmarshal", "参数", "无效选项"} {
		if strings.Contains(s, part) {
			return "argument_format"
		}
	}
	return ""
}
