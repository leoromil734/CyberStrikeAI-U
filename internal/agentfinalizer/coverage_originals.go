package agentfinalizer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
)

var coverageOriginalRoots sync.Map // *database.DB -> trusted service spool root

// ConfigureCoverageOriginals must be called at service startup with the SAME
// trusted root used by resultPipeline. Never pass a model/tool-returned path.
// An empty root removes configuration (also useful when closing a test DB).
func ConfigureCoverageOriginals(db *database.DB, trustedRoot string) error {
	if db == nil {
		return evidence.ErrDenied
	}
	if trustedRoot == "" {
		coverageOriginalRoots.Delete(db)
		return nil
	}
	root, err := filepath.Abs(trustedRoot)
	if err != nil {
		return err
	}
	if strings.HasPrefix(root, `\\`) || strings.HasPrefix(root, "//") || strings.Contains(strings.TrimPrefix(root, filepath.VolumeName(root)), ":") {
		return evidence.ErrUnsafePath
	}
	coverageOriginalRoots.Store(db, root)
	return nil
}

// loadHTTPOriginals adds only opaque verified observations. Failed or unsupported
// candidates remain unverified and never increment independent progress.
func loadHTTPOriginals(db *database.DB, project, conversation, assessment string, index *coverageSourceIndex) error {
	configured, ok := coverageOriginalRoots.Load(db)
	if !ok {
		return nil
	} // explicit integration seam; no guessed filesystem roots
	binding, err := db.CoverageOriginalBinding(project, conversation, assessment)
	if err != nil {
		return fmt.Errorf("HTTP original binding unavailable")
	}
	ctx := evidence.WithAccess(context.Background(), binding.Access)
	index.binding = binding
	executions, err := db.AssessmentHTTPExecutions(ctx, binding)
	if err != nil {
		return fmt.Errorf("HTTP original execution inventory unavailable")
	}
	var readBytes int64
	for _, e := range executions {
		artifacts, err := db.ResultArtifacts(ctx, e.ID, 1000, 0)
		if err != nil || len(artifacts) == 1000 {
			return fmt.Errorf("HTTP original artifact inventory incomplete")
		}
		var inputs, outputs []evidence.Artifact
		for _, a := range artifacts {
			if a.Kind == "input" {
				inputs = append(inputs, a)
			}
			if a.Kind == "output" || a.Kind == "stdout" {
				outputs = append(outputs, a)
			}
		}
		// Multiple captured inputs/outputs are ambiguous, not a cross-product of
		// snippets from which the model may choose a convenient successful pair.
		if len(inputs) != 1 || len(outputs) != 1 {
			continue
		}
		readBytes += inputs[0].Size + outputs[0].Size
		if readBytes > 128<<20 {
			return fmt.Errorf("HTTP original verification byte budget exceeded; unchecked work retained")
		}
		registry, err := coverageRegistry(db, configured.(string), e)
		if err != nil {
			continue
		}
		observation, verifyErr := coverage.VerifyHTTPOriginal(ctx, registry, binding, e.ID, inputs[0].ID, outputs[0].ID)
		registry.Close()
		if verifyErr != nil {
			continue
		}
		index.addHTTP(observation)
		aliases, aliasErr := db.CoverageSourceAliases(ctx, e, observation.OutputArtifactID())
		if aliasErr != nil {
			return fmt.Errorf("HTTP original source aliases unavailable")
		}
		for _, id := range aliases {
			index.sources[id] = database.AssessmentSourceMetadata{ID: id, ExecutionID: e.ID, ArtifactID: observation.OutputArtifactID(), Tool: e.Tool, State: evidence.Parsed, Completion: evidence.Complete}
			index.byExecution[e.ID] = append(index.byExecution[e.ID], id)
		}
	}
	return nil
}

func coverageRegistry(db *database.DB, root string, e evidence.Execution) (*evidence.Registry, error) {
	reduction, err := evidence.ReductionRoot(root, e)
	if err != nil {
		return nil, err
	}
	roots := []evidence.ManagedRoot{}
	if info, err := os.Lstat(reduction.Path); err == nil && info.IsDir() {
		roots = append(roots, reduction)
	}
	executionDir := filepath.Join(filepath.Dir(reduction.Path), "executions", e.ID)
	if info, err := os.Lstat(executionDir); err == nil && info.IsDir() {
		// Exact capture filenames only. Arbitrary POC-generated output files cannot
		// masquerade as the framework/exec tool's stdout.
		roots = append(roots, evidence.ManagedRoot{Path: executionDir, Access: e.Access, ExecutionID: e.ID, Files: []string{"input.json", "output.txt"}})
	}
	return evidence.NewRegistry(db, roots, coverage.MaxHTTPOriginalBytes)
}

func (index *coverageSourceIndex) addHTTP(o coverage.HTTPObservation) {
	if o.ExecutionID() == "" {
		return
	}
	if index.binding.Owner == "" {
		index.binding = o.Binding()
	}
	if index.binding != o.Binding() {
		return
	}
	if index.http == nil {
		index.http = map[string][]coverage.HTTPObservation{}
	}
	index.http[o.ExecutionID()] = append(index.http[o.ExecutionID()], o)
	id := "http-" + o.OutputArtifactID()
	s := database.AssessmentSourceMetadata{ID: id, ExecutionID: o.ExecutionID(), ArtifactID: o.OutputArtifactID(), Tool: o.Tool(), State: evidence.Parsed, Completion: evidence.Complete}
	index.sources[id] = s
	index.byExecution[s.ExecutionID] = append(index.byExecution[s.ExecutionID], id)
}
