package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"

	"cyberstrike-ai/internal/evidence"
)

// Re-registration of a path must retain its first observed hash, including
// manifests. Tool-generated counts/path hints cannot replace this check.
func (p *resultPipeline) registerJSOriginal(ctx context.Context, e evidence.Execution, registry *evidence.Registry, candidate evidence.Candidate) (evidence.Artifact, error) {
	stored, err := p.db.ResultArtifacts(ctx, e.ID, 1000, 0)
	if err != nil {
		return evidence.Artifact{}, err
	}
	for _, old := range stored {
		if filepath.Clean(old.Path) != filepath.Clean(candidate.Path) {
			continue
		}
		if candidate.ExpectedSHA256 != "" && candidate.ExpectedSHA256 != old.SHA256 {
			return evidence.Artifact{}, evidence.ErrChanged
		}
		candidate.ExpectedSHA256 = old.SHA256
	}
	return registry.Register(ctx, e, candidate)
}

// Only downgrade from the fixed, execution-bound private manifest. Counts and
// path hints from stdout/manifest never become inventory or trusted roots.
func (p *resultPipeline) jsExecutionCompleteness(ctx context.Context, e evidence.Execution, registry *evidence.Registry, roots []evidence.ManagedRoot) evidence.Execution {
	manifestPath := jsManifestPath(e, roots)
	if manifestPath == "" {
		e.Completion = evidence.Partial
		return e
	}
	artifact, err := p.registerJSOriginal(ctx, e, registry, evidence.Candidate{Path: manifestPath, Kind: "manifest", Format: "json", Completion: e.Completion})
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
	if err = decodeJSManifest(file, artifact.Size, &manifest); err != nil || registry.CheckUnchanged(ctx, file, artifact) != nil || !manifest.Complete || !manifest.ScanComplete || !manifest.ExportComplete || !manifest.RawComplete || manifest.Partial || manifest.Cancelled {
		e.Completion = evidence.Partial
	}
	if manifest.TimedOut {
		e.TimedOut = true
		e.Completion = evidence.Partial
	}
	return e
}

func jsManifestPath(e evidence.Execution, roots []evidence.ManagedRoot) string {
	for _, root := range roots {
		if root.ExecutionID == e.ID && root.Access == e.Access && filepath.Base(root.Path) == "execution-"+e.ID {
			return filepath.Join(root.Path, "manifest.json")
		}
	}
	return ""
}

func decodeJSManifest(reader io.Reader, size int64, out interface{}) error {
	if size > 2<<20 {
		return evidence.ErrLimit
	}
	d := json.NewDecoder(io.LimitReader(reader, 2<<20))
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(interface{})) != io.EOF {
		return errors.New("invalid manifest trailing content")
	}
	return nil
}

// jsluice hashes source.js and both raw/normalized results. Only the fixed
// mode-specific filenames below are considered; a manifest cannot add paths.
func (p *resultPipeline) jsluiceResultArtifacts(ctx context.Context, e evidence.Execution, registry *evidence.Registry, roots []evidence.ManagedRoot) (evidence.Execution, []evidence.Candidate, error) {
	path := jsManifestPath(e, roots)
	partial := func() (evidence.Execution, []evidence.Candidate, error) {
		e.Completion = evidence.Partial
		return e, nil, nil
	}
	if path == "" {
		return partial()
	}
	artifact, err := p.registerJSOriginal(ctx, e, registry, evidence.Candidate{Path: path, Kind: "manifest", Format: "json", Completion: e.Completion})
	if err != nil {
		if errors.Is(err, evidence.ErrChanged) {
			return e, nil, err
		}
		return partial()
	}
	file, _, err := registry.OpenVerified(ctx, artifact.ID)
	if err != nil {
		return e, nil, err
	}
	defer file.Close()
	var manifest struct {
		Schema           string `json:"schema"`
		Tool             string `json:"tool"`
		ExecutionID      string `json:"execution_id"`
		Mode             string `json:"mode"`
		SourceSHA256     string `json:"source_sha256"`
		Complete         bool   `json:"complete"`
		AnalysisComplete bool   `json:"analysis_complete"`
		ExportComplete   bool   `json:"export_complete"`
		RawComplete      bool   `json:"raw_complete"`
		Partial          bool   `json:"partial"`
		Cancelled        bool   `json:"cancelled"`
		TimedOut         bool   `json:"timed_out"`
		Files            map[string]struct {
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"files"`
	}
	if err = decodeJSManifest(file, artifact.Size, &manifest); err != nil {
		return partial()
	}
	if err = registry.CheckUnchanged(ctx, file, artifact); err != nil {
		return e, nil, err
	}
	if manifest.Schema != "csai.jsluice.v1" || manifest.Tool != "jsluice" || manifest.ExecutionID != e.ID || (manifest.Mode != "urls" && manifest.Mode != "secrets") {
		return partial()
	}
	if !manifest.Complete || !manifest.AnalysisComplete || !manifest.ExportComplete || !manifest.RawComplete || manifest.Partial || manifest.Cancelled || manifest.TimedOut {
		e.Completion = evidence.Partial
	}
	if manifest.TimedOut {
		e.TimedOut = true
	}
	candidates := []evidence.Candidate{}
	sourceVerified := false
	for _, name := range []string{"source.js", "raw.jsonl", "stderr.log", manifest.Mode + ".jsonl"} {
		entry, ok := manifest.Files[name]
		digest, hashErr := hex.DecodeString(entry.SHA256)
		if !ok || hashErr != nil || len(digest) != 32 || entry.Bytes < 0 {
			e.Completion = evidence.Partial
			continue
		}
		if name == "source.js" && entry.SHA256 != manifest.SourceSHA256 {
			return e, nil, evidence.ErrChanged
		}
		candidate := evidence.Candidate{Path: filepath.Join(filepath.Dir(path), name), Kind: "log", Format: "log", Completion: e.Completion, ExpectedSHA256: entry.SHA256}
		if name == manifest.Mode+".jsonl" {
			// A syntactically valid hash in an exported row cannot substitute
			// for the actual retained and verified JavaScript original.
			if !sourceVerified {
				e.Completion = evidence.Partial
				continue
			}
			candidate.Kind = "output"
			candidate.Format = "jsonl"
		}
		if name == "source.js" {
			candidate.Kind = "source"
			candidate.Format = "javascript"
		}
		registered, err := p.registerJSOriginal(ctx, e, registry, candidate)
		if err != nil {
			return e, nil, err
		}
		if registered.Size != entry.Bytes {
			return e, nil, evidence.ErrChanged
		}
		if name == "source.js" {
			sourceVerified = true
		}
		candidates = append(candidates, candidate)
	}
	// Incomplete source attribution cannot be called a successful extraction.
	if len(candidates) != 4 {
		e.Completion = evidence.Partial
	}
	return e, candidates, nil
}
