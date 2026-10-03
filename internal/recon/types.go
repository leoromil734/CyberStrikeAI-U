// Package recon parses registered local originals. It never runs a scanner,
// follows a URL, promotes a candidate to a finding, or writes project facts.
package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/evidence"
)

const ParserVersion = "core-offline/v1"
const (
	Host            = "host"
	Service         = "service"
	Endpoint        = "endpoint"
	JS              = "js"
	Candidate       = "candidate"
	InScope         = "in_scope"
	OutOfScope      = "out_of_scope"
	UnknownScope    = "unknown"
	MissingOriginal = "missing_original"
)

type Location struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
	Line   int64 `json:"line,omitempty"`
}

// Record is deliberately structural and bounded, without arbitrary raw JSON,
// response bodies or matched secret values. RawURL/RawPath preserve route values.
type Record struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Host          string   `json:"host"`
	RawHost       string   `json:"raw_host"`
	IP            string   `json:"ip,omitempty"`
	Port          int      `json:"port,omitempty"`
	RawPort       string   `json:"raw_port,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	ServiceName   string   `json:"service_name,omitempty"`
	RawURL        string   `json:"raw_url,omitempty"`
	RawPath       string   `json:"raw_path,omitempty"`
	Method        string   `json:"method,omitempty"`
	TemplateID    string   `json:"template_id,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	ScopeState    string   `json:"scope_state"`
	CandidateOnly bool     `json:"candidate_only"`
	ArtifactID    string   `json:"artifact_id,omitempty"`
	ExecutionID   string   `json:"execution_id,omitempty"`
	SourceID      string   `json:"source_id,omitempty"`
	Location      Location `json:"location"`
}

func (r Record) Validate() error {
	switch r.Kind {
	case Host, Service, Endpoint, JS, Candidate:
	default:
		return errors.New("invalid inventory kind")
	}
	if r.Port < 0 || r.Port > 65535 || r.Host == "" && r.RawURL == "" {
		return errors.New("invalid inventory record")
	}
	switch r.ScopeState {
	case InScope, OutOfScope, UnknownScope:
	default:
		return errors.New("invalid inventory scope")
	}
	if (r.ScopeState != InScope || r.Kind == Candidate) && !r.CandidateOnly {
		return errors.New("candidate restriction required")
	}
	for _, s := range []string{r.Host, r.RawHost, r.IP, r.RawPort, r.Protocol, r.ServiceName, r.Method, r.TemplateID, r.Severity} {
		if len(s) > 512 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			return errors.New("oversized inventory field")
		}
	}
	if len(r.RawURL) > 8192 || len(r.RawPath) > 8192 || !utf8.ValidString(r.RawURL) || !utf8.ValidString(r.RawPath) || strings.ContainsRune(r.RawURL, 0) || strings.ContainsRune(r.RawPath, 0) {
		return errors.New("oversized inventory route")
	}
	return nil
}

// Identity includes original URL/query/path/port and scope classification. It
// never collapses /users/1 into /users/:id, or discards query parameter values.
func (r Record) Identity() string {
	data, _ := json.Marshal([]interface{}{r.Kind, r.Host, r.RawHost, r.IP, r.Port, r.RawPort, r.Protocol, r.ServiceName, r.RawURL, r.RawPath, r.Method, r.TemplateID, r.Severity, r.ScopeState, r.CandidateOnly})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type Counts struct {
	Hosts      int64 `json:"hosts"`
	Services   int64 `json:"services"`
	Endpoints  int64 `json:"endpoints"`
	JS         int64 `json:"js"`
	Candidates int64 `json:"candidates"`
}

func (c *Counts) Add(kind string) {
	switch kind {
	case Host:
		c.Hosts++
	case Service:
		c.Services++
	case Endpoint:
		c.Endpoints++
	case JS:
		c.JS++
	case Candidate:
		c.Candidates++
	}
}
func (c Counts) Total() int64 { return c.Hosts + c.Services + c.Endpoints + c.JS + c.Candidates }

type Source struct {
	ID          string `json:"id"`
	ExecutionID string `json:"execution_id"`
	ArtifactID  string `json:"artifact_id"`
	evidence.Access
	ScopeID       string         `json:"scope_id"`
	AssessmentID  string         `json:"assessment_id"`
	SHA256        string         `json:"sha256"`
	Tool          string         `json:"tool"`
	Format        string         `json:"format"`
	ParserVersion string         `json:"parser_version"`
	Completion    string         `json:"completion"`
	State         string         `json:"state"`
	Reason        string         `json:"reason,omitempty"`
	Stats         evidence.Stats `json:"stats"`
	Inserted      Counts         `json:"inserted"`
	ObservedAt    time.Time      `json:"observed_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	Expired       bool           `json:"expired"`
}

func (s Source) Key() string {
	data, _ := json.Marshal([]string{s.ProjectID, s.ConversationID, s.Owner, s.ScopeID, s.AssessmentID, s.ExecutionID, s.SHA256, s.ParserVersion, s.Tool, s.Format})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type ImportResult struct {
	Source    Source `json:"source"`
	Inserted  Counts `json:"inserted"`
	Duplicate bool   `json:"duplicate"`
	// Records is bounded by the parser limit. The processor further bounds the
	// aggregate report; callers may page inventory for asset import instead.
	Records []Record `json:"records,omitempty"`
}

// Ingester implementations atomically import a source, inventory and provenance.
// Duplicate sources return Inserted=0, retaining the historical source delta.
// Queries are anchored to an execution's stored scope/assessment/ownership.
type Ingester interface {
	ImportReconSource(context.Context, Source, []Record) (ImportResult, error)
	ReconInventory(context.Context, string, string, int, int) ([]Record, error)
	ReconInventoryCounts(context.Context, string) (Counts, error)
	ReconSources(context.Context, string, int, int, time.Time) ([]Source, error)
}

type Store interface {
	evidence.Store
	Ingester
}

type Limits struct {
	MaxBytes     int64
	MaxLineBytes int
	MaxRecords   int
}

func (l Limits) normalized() Limits {
	if l.MaxBytes <= 0 || l.MaxBytes > 512<<20 {
		l.MaxBytes = 64 << 20
	}
	if l.MaxLineBytes <= 0 || l.MaxLineBytes > 4<<20 {
		l.MaxLineBytes = 1 << 20
	}
	if l.MaxRecords <= 0 || l.MaxRecords > 100000 {
		l.MaxRecords = 10000
	}
	return l
}

type ScopeResolver func(context.Context, evidence.Execution, Record) string

type Event struct {
	Execution evidence.Execution
	// CappedResult is deliberately ignored by parsers, including its path hints.
	CappedResult string
	Artifacts    []evidence.Candidate
	ExpiresAt    time.Time
}

type RegistrationError struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

type Report struct {
	ExecutionID      string              `json:"execution_id"`
	Artifacts        []evidence.Artifact `json:"artifacts"`
	Sources          []Source            `json:"sources"`
	Inserted         Counts              `json:"inserted"`
	Records          []Record            `json:"records"`
	RecordsTruncated bool                `json:"records_truncated"`
	Inventory        Counts              `json:"inventory"`
	ArtifactErrors   []RegistrationError `json:"artifact_errors,omitempty"`
}

type Observer interface {
	Observe(context.Context, Event) (Report, error)
}
