package recon

import (
	"context"
	"errors"
	"time"

	"cyberstrike-ai/internal/evidence"
)

type Processor struct {
	Store     Store
	Artifacts *evidence.Registry
	Limits    Limits
	// Scope is supplied by the host's authorization policy, not inferred from a
	// hostname suffix, a tool preview, or a previous assessment's inventory.
	Scope              ScopeResolver
	MaxReturnedRecords int
}

// Observe is the tool-finish seam. Metadata is written first, even when output
// registration or parsing fails. CappedResult is never ingested or persisted.
func (p *Processor) Observe(ctx context.Context, event Event) (Report, error) {
	e := event.Execution
	if e.TimedOut {
		e.Completion = evidence.Partial
	}
	report := Report{ExecutionID: e.ID}
	if p.Store == nil || p.Artifacts == nil {
		return report, errors.New("result processor requires a store and registry")
	}
	if err := p.Store.RecordExecution(ctx, e); err != nil {
		return report, err
	}
	maxReturned := p.MaxReturnedRecords
	if maxReturned <= 0 || maxReturned > 10000 {
		maxReturned = 1000
	}
	outputSources := 0
	// Prevent an untrusted manifest from registering an unbounded number of files.
	candidates := event.Artifacts
	if len(candidates) > 256 {
		candidates = candidates[:256]
		report.ArtifactErrors = append(report.ArtifactErrors, RegistrationError{Index: 256, Code: "artifact_count_limit"})
	}
	for index, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		artifact, err := p.Artifacts.Register(ctx, e, candidate)
		if err != nil {
			report.ArtifactErrors = append(report.ArtifactErrors, RegistrationError{Index: index, Code: evidence.ErrorCode(err)})
			continue
		}
		report.Artifacts = append(report.Artifacts, artifact)
		if artifact.Kind == "input" {
			continue
		}
		outputSources++
		result, err := p.process(ctx, e, artifact, event.ExpiresAt)
		if err != nil {
			return report, err
		}
		refreshed, err := p.Store.ResultArtifact(ctx, artifact.ID)
		if err != nil {
			return report, err
		}
		report.Artifacts[len(report.Artifacts)-1] = refreshed
		report.Sources = append(report.Sources, result.Source)
		report.Inserted.Hosts += result.Inserted.Hosts
		report.Inserted.Services += result.Inserted.Services
		report.Inserted.Endpoints += result.Inserted.Endpoints
		report.Inserted.JS += result.Inserted.JS
		report.Inserted.Candidates += result.Inserted.Candidates
		room := maxReturned - len(report.Records)
		if len(result.Records) > room {
			result.Records = result.Records[:room]
			report.RecordsTruncated = true
		}
		report.Records = append(report.Records, result.Records...)
	}
	if outputSources == 0 {
		s := newSource(e, evidence.Artifact{}, event.ExpiresAt)
		s.State = MissingOriginal
		s.Reason = "no_registered_output"
		s.Format = "none"
		s.Completion = evidence.Partial
		if e.Completion == evidence.Error {
			s.Completion = evidence.Error
		}
		if len(report.ArtifactErrors) > 0 {
			s.Reason = "original_rejected"
		}
		result, err := p.Store.ImportReconSource(ctx, s, nil)
		if err != nil {
			return report, err
		}
		report.Sources = append(report.Sources, result.Source)
	}
	var err error
	report.Inventory, err = p.Store.ReconInventoryCounts(ctx, e.ID)
	return report, err
}

func newSource(e evidence.Execution, a evidence.Artifact, expires time.Time) Source {
	observed := e.FinishedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	return Source{ExecutionID: e.ID, ArtifactID: a.ID, Access: e.Access, ScopeID: e.ScopeID, AssessmentID: e.AssessmentID, SHA256: a.SHA256, Tool: CanonicalTool(e.OutputTool()), Format: a.Format, ParserVersion: ParserVersion, Completion: a.Completion, State: evidence.Pending, ObservedAt: observed, ExpiresAt: expires}
}

func (p *Processor) process(ctx context.Context, e evidence.Execution, a evidence.Artifact, expires time.Time) (ImportResult, error) {
	s := newSource(e, a, expires)
	file, _, err := p.Artifacts.OpenVerified(ctx, a.ID)
	if err != nil {
		s.State = evidence.Error
		s.Completion = evidence.Error
		s.Reason = evidence.ErrorCode(err)
		return p.Store.ImportReconSource(ctx, s, nil)
	}
	defer file.Close()
	parsed, err := Parse(ctx, s.Tool, a.Format, file, p.Limits)
	if err != nil {
		return ImportResult{}, err
	}
	if err = p.Artifacts.CheckUnchanged(ctx, file, a); err != nil {
		s.State = evidence.Error
		s.Completion = evidence.Error
		s.Reason = evidence.ErrorCode(err)
		return p.Store.ImportReconSource(ctx, s, nil)
	}
	s.State = parsed.State
	s.Reason = parsed.Reason
	s.Stats = parsed.Stats
	if parsed.Partial || e.TimedOut {
		if s.Completion != evidence.Error {
			s.Completion = evidence.Partial
		}
	}
	if s.Completion != evidence.Complete && s.State == evidence.Parsed {
		s.State = evidence.Partial
	}
	for index := range parsed.Records {
		r := &parsed.Records[index]
		state := UnknownScope
		if p.Scope != nil && e.ProjectID != "" && e.ScopeID != "" && e.AssessmentID != "" {
			state = p.Scope(ctx, e, *r)
		}
		if state != InScope && state != OutOfScope {
			state = UnknownScope
		}
		r.ScopeState = state
		r.CandidateOnly = state != InScope || r.Kind == Candidate || s.Tool == "jsluice" || s.Tool == "jsapiscan" || s.Tool == "crtsh"
		r.ArtifactID = a.ID
		r.ExecutionID = e.ID
	}
	return p.Store.ImportReconSource(ctx, s, parsed.Records)
}

var _ Observer = (*Processor)(nil)
