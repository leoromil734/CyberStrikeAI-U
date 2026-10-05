package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/recon"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type resultPipeline struct {
	db     *database.DB
	root   string
	logger *zap.Logger
	wake   chan struct{}
}

// Only wakeups are buffered. Raw results and pending/retry jobs live in the DB;
// the two workers load one claimed snapshot each, never an in-memory backlog.
func newResultPipeline(db *database.DB, cfg *config.Config, logger *zap.Logger) *resultPipeline {
	p := offlineResultPipeline(db, cfg, logger)
	for i := 0; i < 2; i++ {
		go p.worker(context.Background())
	}
	return p
}

func (p *resultPipeline) observe(ctx context.Context, original *mcp.ToolExecution) {
	if original == nil || original.ID == "" || original.OwnerUserID == "" || original.ConversationID == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if principal, ok := authctx.PrincipalFromContext(ctx); ok && principal.UserID != original.OwnerUserID {
		p.logger.Warn("执行身份与原件所有者不一致", zap.String("executionId", original.ID))
		return
	}
	projectID, scopeID, assessmentID := "", "", ""
	bindingErr := p.db.QueryRow(`SELECT project_id,scope_id,assessment_id FROM result_execution_metadata WHERE execution_id=? AND owner=? AND conversation_id=?`, original.ID, original.OwnerUserID, original.ConversationID).Scan(&projectID, &scopeID, &assessmentID)
	if bindingErr != nil {
		if !errors.Is(bindingErr, sql.ErrNoRows) {
			p.logger.Warn("读取执行原件绑定失败", zap.String("executionId", original.ID), zap.Error(bindingErr))
			return
		}
		var err error
		projectID, err = p.db.GetConversationProjectID(original.ConversationID)
		if err != nil {
			p.logger.Warn("无法绑定执行原件项目", zap.String("executionId", original.ID), zap.Error(err))
			return
		}
		if bound := mcp.MCPProjectIDFromContext(ctx); bound != "" {
			projectID = bound
		}
	}
	access := evidence.Access{ProjectID: projectID, ConversationID: original.ConversationID, Owner: original.OwnerUserID}
	ctx = evidence.WithAccess(context.WithoutCancel(ctx), access)
	e := evidence.Execution{ID: original.ID, Access: access, Tool: original.ToolName, Status: original.Status, Completion: evidence.Complete, StartedAt: original.StartTime}
	if original.ToolName == "exec" || original.ToolName == "execute" {
		e.ParserTool = trustedDirectScanner(original.Arguments)
	}
	if original.EndTime != nil {
		e.FinishedAt = *original.EndTime
	}
	if original.Status != mcp.ToolExecutionStatusCompleted {
		e.Completion = evidence.Partial
	}
	e.TimedOut = original.Status == mcp.ToolExecutionStatusHardTimeout
	text := mcp.ToolResultPlainText(original.Result)
	e.Capped = strings.Contains(text, "<persisted-output>") || original.PartialOutputTruncated
	e.OutputBytes = int64(len(text))
	// Resolve the run by start time, not whichever continuation is newest now.
	var assessment string
	_ = p.db.QueryRow(`SELECT assessment_id FROM assessment_runs WHERE conversation_id=? AND started_at<=? ORDER BY started_at DESC,id DESC LIMIT 1`, e.ConversationID, e.StartedAt).Scan(&assessment)
	e.AssessmentID = assessment
	if bindingErr == nil {
		e.AssessmentID = assessmentID
		e.ScopeID = scopeID
	} else if projectID != "" {
		if project, getErr := p.db.GetProject(projectID); getErr == nil {
			sum := sha256.Sum256([]byte(project.ScopeJSON))
			e.ScopeID = "scope-" + hex.EncodeToString(sum[:16])
		}
	}
	if original.EndTime == nil || builtin.IsBuiltinTool(e.Tool) {
		if err := p.db.RecordExecution(ctx, e); err != nil {
			p.logger.Warn("保存原件执行元数据失败", zap.String("executionId", e.ID), zap.Error(err))
		}
		return
	}
	// The observer runs before ordinary monitor persistence. Persist the result,
	// binding, snapshot and job atomically before signalling either worker.
	if err := p.db.PersistResultIngestion(ctx, e, original, p.ingestionProjection(ctx, e)); err != nil {
		p.logger.Error("持久化原件处理任务失败", zap.String("executionId", e.ID), zap.Error(err))
		return
	}
	select {
	case p.wake <- struct{}{}:
	default:
		// Signals may coalesce. The database, not this channel, owns every job.
	}
}

// Paths are derived from trusted configuration and persisted binding. Returned
// work_dir/path hints in stdout and manifests never become managed roots.
func (p *resultPipeline) roots(e evidence.Execution) ([]evidence.ManagedRoot, error) {
	reduction, err := evidence.ReductionRoot(p.root, e)
	if err != nil {
		return nil, err
	}
	roots := []evidence.ManagedRoot{}
	if info, err := os.Lstat(reduction.Path); err == nil && info.IsDir() {
		roots = append(roots, reduction)
	}
	dir := filepath.Join(filepath.Dir(reduction.Path), "executions", e.ID)
	if info, err := os.Lstat(dir); err == nil && info.IsDir() {
		roots = append(roots, evidence.ManagedRoot{Path: dir, Access: e.Access, ExecutionID: e.ID})
	}
	tool := recon.CanonicalTool(e.OutputTool())
	if tool == "jsapiscan" || tool == "jsluice" {
		if id, err := uuid.Parse(e.ID); err == nil && id.String() == e.ID {
			// CSAI_ARTIFACT_DIR is derived by Executor from the same reduction
			// root and immutable binding. Never read tool-reported work_dir.
			workspace := filepath.Join(dir, tool, "execution-"+id.String())
			if info, err := os.Lstat(workspace); err == nil {
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return nil, evidence.ErrUnsafePath
				}
				roots = append(roots, evidence.ManagedRoot{Path: workspace, Access: e.Access, ExecutionID: e.ID})
			} else if !os.IsNotExist(err) {
				return nil, err
			} else if tool == "jsapiscan" {
				legacy := filepath.Join(string(filepath.Separator), "var", "lib", "jsapiscan", "runs", "execution-"+id.String())
				if info, err := os.Lstat(legacy); err == nil && info.IsDir() {
					roots = append(roots, evidence.ManagedRoot{Path: legacy, Access: e.Access, ExecutionID: e.ID})
				}
			}
		}
	}
	return roots, nil
}

func (p *resultPipeline) process(ctx context.Context, e evidence.Execution, original *mcp.ToolExecution) (state, reason string, err error) {
	state, reason = "failed", "original processing failed; metadata retained"
	if err = checkIngestionClaim(ctx, p.db); err != nil {
		return
	}
	reduction, err := evidence.ReductionRoot(p.root, e)
	if err != nil {
		reason = "unsafe execution binding"
		return
	}
	dir := filepath.Join(filepath.Dir(reduction.Path), "executions", e.ID)
	// Include the full immutable binding, not only the path components. A file
	// from another owner, assessment or scope must never be silently reused.
	binding, marshalErr := json.Marshal(struct {
		ID string `json:"execution_id"`
		evidence.Access
		AssessmentID string `json:"assessment_id"`
		ScopeID      string `json:"scope_id"`
		Tool         string `json:"tool"`
	}{e.ID, e.Access, e.AssessmentID, e.ScopeID, e.Tool})
	if marshalErr != nil {
		return "failed", "execution binding serialization failed", marshalErr
	}
	if err = writeManagedOriginal(dir, "binding.json", binding); err != nil {
		return "failed", "managed original binding conflicts or is unsafe", err
	}
	args, err := json.Marshal(original.Arguments)
	if err != nil {
		return "failed", "input metadata serialization failed", err
	}
	if len(args) > 4<<20 {
		return "failed", "input metadata exceeds 4MiB", evidence.ErrLimit
	}
	if err = writeManagedOriginal(dir, "input.json", args); err != nil {
		reason = "input original could not be safely created"
		return
	}
	candidates := []evidence.Candidate{{Path: filepath.Join(dir, "input.json"), Kind: "input", Format: "json", Completion: e.Completion}}
	output := filepath.Join(reduction.Path, e.ID)
	missingPersistedOutput := false
	info, statErr := os.Lstat(output)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "failed", "saved output path is not a regular original", evidence.ErrUnsafePath
		}
		e.OutputBytes = info.Size()
		if info.Size() > int64(len(mcp.ToolResultPlainText(original.Result))) {
			e.Capped = true
		}
		candidates = append(candidates, evidence.Candidate{Path: output, Kind: "output", Format: resultFormat(e.OutputTool(), original.Arguments), Completion: e.Completion})
	} else {
		if !os.IsNotExist(statErr) {
			return "failed", "saved output path unavailable", statErr
		}
		text := mcp.ToolResultPlainText(original.Result)
		missingPersistedOutput = strings.Contains(text, "<persisted-output>")
		if missingPersistedOutput {
			// A reduced preview is not the original. Retain the input, but
			// never report complete merely because its registration succeeds.
			e.Completion = evidence.Partial
			e.Capped = true
		}
		if text != "" && !missingPersistedOutput {
			if err = writeManagedOriginal(dir, "output.txt", []byte(text)); err != nil {
				reason = "output original could not be safely created"
				return
			}
			candidates = append(candidates, evidence.Candidate{Path: filepath.Join(dir, "output.txt"), Kind: "output", Format: resultFormat(e.OutputTool(), original.Arguments), Completion: e.Completion})
		}
	}
	// Independent machine originals win over combined stdout/stderr. The fixed
	// names are a service/runner contract, never filenames advertised by output.
	machineName, machineFormat := "", ""
	switch recon.CanonicalTool(e.OutputTool()) {
	case "nmap":
		machineName, machineFormat = "nmap.xml", "xml"
	case "nuclei":
		machineName, machineFormat = "nuclei.jsonl", "jsonl"
	}
	if machineName != "" {
		machinePath := filepath.Join(dir, machineName)
		if _, statErr := os.Lstat(machinePath); statErr == nil {
			for i := range candidates {
				if candidates[i].Kind == "output" {
					candidates[i].Kind = "log"
					candidates[i].Format = "log"
				}
			}
			candidates = append(candidates, evidence.Candidate{Path: machinePath, Kind: "output", Format: machineFormat, Completion: e.Completion})
		} else if !os.IsNotExist(statErr) {
			return "failed", "machine original unavailable", statErr
		}
	}
	roots, err := p.roots(e)
	if err != nil {
		reason = "managed roots unavailable"
		return
	}
	// Actual CSV originals preserve exact route/query values. Candidate exports
	// contain templates and never substitute for the originals.
	if recon.CanonicalTool(e.OutputTool()) == "jsapiscan" {
		for _, root := range roots {
			if filepath.Base(root.Path) != "execution-"+e.ID {
				continue
			}
			count := 0
			walkErr := filepath.WalkDir(filepath.Join(root.Path, "work"), func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if d.Type()&os.ModeSymlink != 0 {
					e.Completion = evidence.Partial
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".csv") {
					if count >= 200 {
						e.Completion = evidence.Partial
						return fs.SkipAll
					}
					count++
					candidates = append(candidates, evidence.Candidate{Path: path, Kind: "output", Format: "csv", Completion: e.Completion})
				}
				return nil
			})
			if walkErr != nil {
				e.Completion = evidence.Partial
			}
		}
	}
	// A retry may reuse a saved spill/CSV only at the previously registered
	// hash. A different body at the same path must not create a second source.
	registered, err := p.db.ResultArtifacts(ctx, e.ID, 1000, 0)
	if err != nil {
		return "failed", "registered original metadata unavailable", err
	}
	for i := range candidates {
		for _, a := range registered {
			if filepath.Clean(a.Path) == filepath.Clean(candidates[i].Path) {
				if candidates[i].ExpectedSHA256 != "" && candidates[i].ExpectedSHA256 != a.SHA256 {
					return "failed", "multiple hashes recorded for original path", evidence.ErrChanged
				}
				candidates[i].ExpectedSHA256 = a.SHA256
			}
		}
	}
	store := ingestionStore{DB: p.db}
	registry, err := evidence.NewRegistry(store, roots, evidence.DefaultMaxArtifactBytes)
	if err != nil {
		reason = "unsafe or missing managed artifact root"
		return
	}
	defer registry.Close()
	if recon.CanonicalTool(e.OutputTool()) == "jsapiscan" {
		e = p.jsExecutionCompleteness(ctx, e, registry, roots)
	}
	if recon.CanonicalTool(e.OutputTool()) == "jsluice" {
		var jsArtifacts []evidence.Candidate
		e, jsArtifacts, err = p.jsluiceResultArtifacts(ctx, e, registry, roots)
		if err != nil {
			return "failed", "JS original hash or binding rejected", err
		}
		candidates = append(candidates, jsArtifacts...)
	}
	for i := range candidates {
		candidates[i].Completion = e.Completion
	}
	// Unknown task scope stays candidate-only. Neither a project name nor a
	// target in a tool argument is a grant to expand the original task scope.
	processor := recon.Processor{Store: store, Artifacts: registry, MaxReturnedRecords: 1000, Limits: recon.Limits{MaxRecords: 100000}}
	logs := []evidence.Candidate{}
	machine := []evidence.Candidate{}
	for _, candidate := range candidates {
		if candidate.Format == "log" || candidate.Kind == "source" {
			if candidate.Kind == "output" {
				candidate.Kind = "log"
			}
			logs = append(logs, candidate)
		} else {
			machine = append(machine, candidate)
		}
	}
	candidates = machine
	report, err := processor.Observe(ctx, recon.Event{Execution: e, Artifacts: candidates, ExpiresAt: e.FinishedAt.Add(24 * time.Hour)})
	if err != nil {
		reason = "offline original registration/parsing failed"
		p.logger.Warn(reason, zap.String("executionId", e.ID), zap.Error(err))
		return
	}
	state, reason = "complete", ""
	for _, candidate := range logs {
		artifact, logErr := registry.Register(ctx, e, candidate)
		if logErr != nil {
			return "failed", "log original registration failed", logErr
		}
		report.Artifacts = append(report.Artifacts, artifact)
	}
	if len(report.ArtifactErrors) > 0 {
		state, reason = "partial", "one or more originals were rejected or exceeded limits"
		for _, rejected := range report.ArtifactErrors {
			switch rejected.Code {
			case "original_changed":
				return "failed", "registered original hash changed", evidence.ErrChanged
			case "access_denied":
				return "failed", "original registration binding denied", evidence.ErrDenied
			case "original_unavailable":
				return "failed", "original registration unavailable", errors.New("original registration unavailable")
			}
		}
	}
	if e.Completion != evidence.Complete {
		state, reason = "partial", "execution result is partial or timed out; original retained"
	}
	for _, source := range report.Sources {
		if source.State == recon.MissingOriginal || source.State == evidence.Error || source.State == evidence.Invalid {
			state, reason = "partial", "source is missing or invalid; saved evidence retained"
		}
	}
	if reconTool(e.OutputTool()) {
		parsed := false
		for _, source := range report.Sources {
			if source.State == evidence.Parsed || source.State == evidence.Partial {
				parsed = true
			}
			if source.Completion != evidence.Complete {
				state, reason = "partial", "source is partial or timed out; original retained"
			}
		}
		if !parsed {
			state, reason = "partial", "no supported machine-readable original; use explicit artifact registration"
		}
	}
	if missingPersistedOutput {
		state, reason = "partial", "persisted-output preview has no retained output original; input and available evidence retained"
	}
	if err = p.importRecon(ctx, e, report); err != nil {
		state, reason = "failed", "inventory saved but asset/candidate projection incomplete"
		p.logger.Warn(reason, zap.String("executionId", e.ID), zap.Error(err))
	}
	return
}

func (p *resultPipeline) importRecon(ctx context.Context, e evidence.Execution, report recon.Report) error {
	if e.ProjectID == "" {
		return nil
	}
	principal, authenticated := authctx.PrincipalFromContext(ctx)
	authenticated = authenticated && principal.UserID == e.Owner
	canProject := authenticated && principal.HasPermission("project:write") && p.db.UserCanAccessResource(principal.UserID, principal.ScopeFor("project:write"), "project", e.ProjectID)
	canAsset := authenticated && principal.HasPermission("asset:write") && p.db.UserCanAccessResource(principal.UserID, principal.ScopeFor("asset:write"), "project", e.ProjectID)
	if !canProject && !canAsset {
		return nil
	}
	var claim *database.ResultIngestionJob
	if job, ok := ctx.Value(ingestionClaimContextKey{}).(database.ResultIngestionJob); ok {
		claim = &job
	}
	// Page the stored source records, not the bounded model-facing report.
	for _, source := range report.Sources {
		if err := checkIngestionClaim(ctx, p.db); err != nil {
			return err
		}
		if canProject && e.AssessmentID != "" && reconTool(e.OutputTool()) {
			if err := p.saveReconSourceFact(e, source); err != nil {
				return err
			}
		}
		for offset := 0; ; offset += 500 {
			records, err := p.db.ReconSourceRecords(ctx, source.ID, 500, offset)
			if err != nil {
				return err
			}
			if len(records) == 0 {
				break
			}
			assets := []*database.Asset{}
			for _, record := range records {
				if canAsset && (record.Kind == recon.Host || record.Kind == recon.Service) {
					domain, ip := record.Host, record.IP
					if net.ParseIP(domain) != nil {
						ip = domain
						domain = ""
					}
					assets = append(assets, &database.Asset{ProjectID: e.ProjectID, Host: record.Host, Domain: domain, IP: ip, Port: record.Port, Protocol: record.Protocol, Status: "inactive", Source: "recon:" + source.Tool, SourceQuery: "execution:" + e.ID,
						Observation: &database.AssetObservation{ConversationID: e.ConversationID, ExecutionID: e.ID, ObservedAt: e.FinishedAt}})
				}
				if canProject && record.Kind == recon.Candidate {
					c := &database.FindingCandidate{ProjectID: e.ProjectID, ConversationID: e.ConversationID, AssessmentID: e.AssessmentID, Target: record.RawURL, Title: record.TemplateID, RiskFamily: "scanner_match", ImpactClass: "unknown", Status: "tentative", Summary: "离线导入的扫描命中；未经安全边界与可复现证据校验。", EvidenceRefs: []string{"execution:" + e.ID}, Priority: 50}
					if source.Tool == "jsluice" {
						c.RiskFamily = "static_secret"
						c.Summary = "本地 JS 静态秘密样式候选；始终 tentative，未请求目标、未验证有效性或安全边界。"
					}
					if c.Target == "" {
						c.Target = record.Host
					}
					if c.Title == "" {
						c.Title = "scanner match"
					}
					if err := p.db.ImportResultIngestionCandidate(ctx, e, c, claim); err != nil {
						return err
					}
				}
			}
			if len(assets) > 0 {
				if err := p.db.ImportResultIngestionAssets(ctx, e, assets, claim); err != nil {
					return err
				}
			}
			if len(records) < 500 {
				break
			}
		}
	}
	return nil
}

// compactResultReport is suitable for tool responses: originals remain private.
func compactResultReport(report recon.Report) map[string]interface{} {
	return map[string]interface{}{"execution_id": report.ExecutionID, "artifacts": report.Artifacts, "sources": report.Sources, "inserted": report.Inserted, "inventory": report.Inventory, "records_truncated": report.RecordsTruncated, "artifact_errors": report.ArtifactErrors, "candidate_only": true, "verification": "unverified"}
}
