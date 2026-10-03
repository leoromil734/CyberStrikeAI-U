// Package evidence manages local originals without exposing a general-purpose
// file reader. It has no dependency on MCP, the database, or network clients.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrDenied     = errors.New("evidence access denied")
	ErrUnsafePath = errors.New("unsafe artifact path")
	ErrChanged    = errors.New("artifact changed since registration")
	ErrLimit      = errors.New("evidence limit exceeded")
)

const (
	Complete    = "complete"
	Partial     = "partial"
	Error       = "error"
	Pending     = "pending"
	Parsed      = "parsed"
	Unsupported = "unsupported"
	Invalid     = "invalid"
)

// Access must be obtained from the authenticated execution context by the caller.
// There is deliberately no all-project or implicit administrator bypass here.
type Access struct {
	ProjectID      string `json:"project_id"`
	ConversationID string `json:"conversation_id"`
	Owner          string `json:"owner"`
}

type accessKey struct{}

func WithAccess(ctx context.Context, access Access) context.Context {
	return context.WithValue(ctx, accessKey{}, access)
}

func AccessFromContext(ctx context.Context) (Access, error) {
	a, ok := ctx.Value(accessKey{}).(Access)
	if !ok || a.Owner == "" || a.ConversationID == "" {
		return Access{}, ErrDenied
	}
	return a, nil
}

func (a Access) Authorize(ctx context.Context) error {
	actual, err := AccessFromContext(ctx)
	if err != nil || actual != a {
		return ErrDenied
	}
	return ctx.Err()
}

// Execution contains metadata only. Arguments, previews and tool output are
// never persisted here; a caller may register an input original separately.
type Execution struct {
	ID string `json:"execution_id"`
	Access
	ScopeID      string `json:"scope_id"`
	AssessmentID string `json:"assessment_id"`
	Tool         string `json:"tool"`
	// ParserTool is a trusted scanner identity for a generic executor such as
	// exec. It must come from the dispatched tool/command, never from a preview.
	ParserTool  string    `json:"parser_tool,omitempty"`
	Status      string    `json:"status"`
	Completion  string    `json:"completion"`
	TimedOut    bool      `json:"timed_out"`
	Capped      bool      `json:"capped"`
	OutputBytes int64     `json:"output_bytes"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
}

func (e Execution) Validate(ctx context.Context) error {
	if err := e.Access.Authorize(ctx); err != nil {
		return err
	}
	if e.ID == "" || len(e.ID) > 256 || e.Tool == "" || len(e.Tool) > 128 || len(e.ParserTool) > 128 || len(e.Status) > 64 || e.OutputBytes < 0 {
		return fmt.Errorf("invalid execution metadata")
	}
	for _, s := range []string{e.ProjectID, e.ConversationID, e.Owner, e.ScopeID, e.AssessmentID} {
		if len(s) > 256 {
			return fmt.Errorf("invalid execution binding")
		}
	}
	if !ValidCompletion(e.Completion) {
		return fmt.Errorf("invalid execution completeness")
	}
	return nil
}

func (e Execution) OutputTool() string {
	if e.ParserTool != "" {
		return e.ParserTool
	}
	return e.Tool
}

func ValidCompletion(s string) bool { return s == Complete || s == Partial || s == Error }

// Stats are bounded counters, not a free-form map capable of holding log data.
type Stats struct {
	Records    int64 `json:"records"`
	Rejected   int64 `json:"rejected"`
	Hosts      int64 `json:"hosts"`
	Services   int64 `json:"services"`
	Endpoints  int64 `json:"endpoints"`
	JS         int64 `json:"js"`
	Candidates int64 `json:"candidates"`
}

type Artifact struct {
	ID          string `json:"id"`
	ExecutionID string `json:"execution_id"`
	Access
	Kind       string    `json:"kind"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	Format     string    `json:"format"`
	Completion string    `json:"completion"`
	ParseState string    `json:"parse_state"`
	Stats      Stats     `json:"stats"`
	CreatedAt  time.Time `json:"created_at"`
}

// Store implementations must check the context AND stored execution binding on
// every read/write. RegisterArtifact takes an opaque verification token so a
// caller cannot manufacture a verified path by constructing an Artifact.
type Store interface {
	RecordExecution(context.Context, Execution) error
	ResultExecution(context.Context, string) (Execution, error)
	RegisterArtifact(context.Context, VerifiedArtifact) (Artifact, error)
	ResultArtifact(context.Context, string) (Artifact, error)
	ResultArtifacts(context.Context, string, int, int) ([]Artifact, error)
}

// Candidate is untrusted tool-reported metadata; size/hash are always recomputed.
type Candidate struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	Format         string `json:"format"`
	Completion     string `json:"completion"`
	ExpectedSHA256 string `json:"sha256,omitempty"`
}

type VerifiedArtifact struct {
	artifact Artifact
	verified bool
}

func (v VerifiedArtifact) Metadata() (Artifact, error) {
	if !v.verified {
		return Artifact{}, ErrUnsafePath
	}
	return v.artifact, nil
}
