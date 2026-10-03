package app

import (
	"context"
	"cyberstrike-ai/internal/evidence"
	"encoding/json"
	"io"
	"path/filepath"
)

// Only downgrade from the fixed, execution-bound private manifest. Counts and
// path hints from stdout/manifest never become inventory or trusted roots.
func (p *resultPipeline) jsExecutionCompleteness(ctx context.Context, e evidence.Execution, registry *evidence.Registry, roots []evidence.ManagedRoot) evidence.Execution {
	manifestPath := ""
	for _, root := range roots {
		if filepath.Base(root.Path) == "execution-"+e.ID {
			manifestPath = filepath.Join(root.Path, "manifest.json")
			break
		}
	}
	if manifestPath == "" {
		e.Completion = evidence.Partial
		return e
	}
	artifact, err := registry.Register(ctx, e, evidence.Candidate{Path: manifestPath, Kind: "manifest", Format: "json", Completion: e.Completion})
	if err != nil {
		e.Completion = evidence.Partial
		return e
	}
	file, _, err := registry.OpenVerified(ctx, artifact.ID)
	if err != nil {
		e.Completion = evidence.Partial
		return e
	}
	defer file.Close()
	var manifest struct {
		Complete       bool `json:"complete"`
		ScanComplete   bool `json:"scan_complete"`
		ExportComplete bool `json:"export_complete"`
		RawComplete    bool `json:"raw_complete"`
		TimedOut       bool `json:"timed_out"`
		Partial        bool `json:"partial"`
		Cancelled      bool `json:"cancelled"`
	}
	if err = json.NewDecoder(io.LimitReader(file, 2<<20)).Decode(&manifest); err != nil || registry.CheckUnchanged(ctx, file, artifact) != nil || !manifest.Complete || !manifest.ScanComplete || !manifest.ExportComplete || !manifest.RawComplete || manifest.Partial || manifest.Cancelled {
		e.Completion = evidence.Partial
	}
	if manifest.TimedOut {
		e.TimedOut = true
		e.Completion = evidence.Partial
	}
	return e
}
