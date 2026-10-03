package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type resultJob struct {
	ctx       context.Context
	execution evidence.Execution
	original  *mcp.ToolExecution
}
type resultPipeline struct {
	db     *database.DB
	root   string
	logger *zap.Logger
	jobs   chan resultJob
}

// No network requests or proof execution take place here. The bounded queue is
// deliberately separate from task scheduling and external-tool concurrency.
func newResultPipeline(db *database.DB, cfg *config.Config, logger *zap.Logger) *resultPipeline {
	p := &resultPipeline{db: db, root: cfg.MultiAgent.EinoMiddleware.ReductionRootDir, logger: logger, jobs: make(chan resultJob, 64)}
	if err := db.ReconcileResultIngestionJobs(); err != nil {
		logger.Warn("恢复原件入库队列失败", zap.Error(err))
	}
	for i := 0; i < 2; i++ {
		go func() {
			for job := range p.jobs {
				p.process(job)
			}
		}()
	}
	return p
}

func reconTool(name string) bool {
	switch recon.CanonicalTool(name) {
	case "fofa", "subfinder", "oneforall", "dnsx", "httpx", "naabu", "nmap", "gau", "katana", "jsapiscan", "nuclei":
		return true
	}
	return false
}

func (p *resultPipeline) observe(ctx context.Context, original *mcp.ToolExecution) {
	if original == nil || original.ID == "" || original.OwnerUserID == "" || original.ConversationID == "" {
		return
	}
	projectID, err := p.db.GetConversationProjectID(original.ConversationID)
	if err != nil {
		p.logger.Warn("无法绑定执行原件项目", zap.String("executionId", original.ID))
		return
	}
	scopeID, assessmentID := "", ""
	bindingErr := p.db.QueryRow(`SELECT project_id,scope_id,assessment_id FROM result_execution_metadata WHERE execution_id=? AND owner=? AND conversation_id=?`, original.ID, original.OwnerUserID, original.ConversationID).Scan(&projectID, &scopeID, &assessmentID)
	if bindingErr != nil {
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
	if err = p.db.RecordExecution(ctx, e); err != nil {
		p.logger.Warn("保存原件执行元数据失败", zap.String("executionId", e.ID), zap.Error(err))
		return
	}
	if original.EndTime == nil {
		return
	}
	// Builtins already persist their compact result; no duplicate fact body files.
	if builtin.IsBuiltinTool(e.Tool) {
		return
	}
	if err = p.db.SetResultIngestionState(ctx, e, "pending", ""); err != nil {
		p.logger.Warn("登记原件处理状态失败", zap.String("executionId", e.ID), zap.Error(err))
		return
	}
	select {
	case p.jobs <- resultJob{ctx: ctx, execution: e, original: original}:
	default:
		_ = p.db.SetResultIngestionState(ctx, e, "failed", "bounded ingestion queue full; original retained, reimport required")
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
	if recon.CanonicalTool(e.OutputTool()) == "jsapiscan" {
		if id, err := uuid.Parse(e.ID); err == nil {
			dir = filepath.Join(string(filepath.Separator), "var", "lib", "jsapiscan", "runs", "execution-"+id.String())
			if info, err := os.Lstat(dir); err == nil && info.IsDir() {
				roots = append(roots, evidence.ManagedRoot{Path: dir, Access: e.Access, ExecutionID: e.ID})
			}
		}
	}
	return roots, nil
}

// Each path component is checked before an exclusive file create. Registry
// rechecks confinement and links before any file is ingested or returned.
func makeManagedDirectory(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return evidence.ErrUnsafePath
	}
	parent := filepath.Dir(path)
	if parent != path {
		if err := makeManagedDirectory(parent); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err = os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return evidence.ErrUnsafePath
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(filepath.Clean(resolved), path) {
		return evidence.ErrUnsafePath
	}
	return nil
}
func writeManagedOriginal(dir, name string, data []byte) error {
	if err := makeManagedDirectory(dir); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func resultFormat(tool string, args map[string]interface{}) string {
	if command, ok := args["command"].(string); ok && trustedDirectScanner(args) != "" {
		fields := strings.Fields(command)
		for i, flag := range fields {
			if flag == "-json" || flag == "-jsonl" || flag == "-j" {
				return "jsonl"
			}
			if flag == "-oX" && i+1 < len(fields) && fields[i+1] == "-" {
				return "xml"
			}
		}
	}
	switch recon.CanonicalTool(tool) {
	case "fofa":
		return "json"
	case "nmap":
		return "text"
	case "nuclei":
		if args["json_output"] == true || args["jsonl"] == true {
			return "jsonl"
		}
		return "text"
	case "jsapiscan":
		return "log"
	}
	for _, key := range []string{"json", "json_output", "jsonl", "json_lines"} {
		if args[key] == true {
			return "jsonl"
		}
	}
	return "text"
}

func (p *resultPipeline) process(job resultJob) {
	ctx, cancel := context.WithTimeout(job.ctx, 2*time.Minute)
	defer cancel()
	e := job.execution
	state, reason := "failed", "original processing failed; metadata retained"
	defer func() {
		if recover() != nil {
			state, reason = "failed", "offline ingestion panic; original retained"
		}
		_ = p.db.SetResultIngestionState(context.WithoutCancel(job.ctx), e, state, reason)
	}()
	reduction, err := evidence.ReductionRoot(p.root, e)
	if err != nil {
		reason = "unsafe execution binding"
		return
	}
	dir := filepath.Join(filepath.Dir(reduction.Path), "executions", e.ID)
	args, err := json.Marshal(job.original.Arguments)
	if err != nil || len(args) > 4<<20 {
		reason = "input metadata exceeds 4MiB"
		return
	}
	if err = writeManagedOriginal(dir, "input.json", args); err != nil {
		reason = "input original could not be safely created"
		return
	}
	candidates := []evidence.Candidate{{Path: filepath.Join(dir, "input.json"), Kind: "input", Format: "json", Completion: e.Completion}}
	output := filepath.Join(reduction.Path, e.ID)
	if info, err := os.Lstat(output); err == nil && info.Mode().IsRegular() {
		e.OutputBytes = info.Size()
		if info.Size() > int64(len(mcp.ToolResultPlainText(job.original.Result))) {
			e.Capped = true
		}
		candidates = append(candidates, evidence.Candidate{Path: output, Kind: "output", Format: resultFormat(e.OutputTool(), job.original.Arguments), Completion: e.Completion})
	} else {
		text := mcp.ToolResultPlainText(job.original.Result)
		if text != "" && !strings.Contains(text, "<persisted-output>") {
			if err = writeManagedOriginal(dir, "output.txt", []byte(text)); err != nil {
				reason = "output original could not be safely created"
				return
			}
			candidates = append(candidates, evidence.Candidate{Path: filepath.Join(dir, "output.txt"), Kind: "output", Format: resultFormat(e.OutputTool(), job.original.Arguments), Completion: e.Completion})
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
			if !strings.Contains(root.Path, "execution-") {
				continue
			}
			count := 0
			_ = filepath.WalkDir(filepath.Join(root.Path, "work"), func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if d.Type()&os.ModeSymlink != 0 {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".csv") {
					if count >= 200 {
						return fs.SkipAll
					}
					count++
					candidates = append(candidates, evidence.Candidate{Path: path, Kind: "output", Format: "csv", Completion: e.Completion})
				}
				return nil
			})
		}
	}
	registry, err := evidence.NewRegistry(p.db, roots, evidence.DefaultMaxArtifactBytes)
	if err != nil {
		reason = "unsafe or missing managed artifact root"
		return
	}
	defer registry.Close()
	if recon.CanonicalTool(e.OutputTool()) == "jsapiscan" {
		e = p.jsExecutionCompleteness(ctx, e, registry, roots)
		for i := range candidates {
			candidates[i].Completion = e.Completion
		}
	}
	// Unknown task scope stays candidate-only. Neither a project name nor a
	// target in a tool argument is a grant to expand the original task scope.
	processor := recon.Processor{Store: p.db, Artifacts: registry, MaxReturnedRecords: 1000, Limits: recon.Limits{MaxRecords: 100000}}
	logs := []evidence.Candidate{}
	if recon.CanonicalTool(e.OutputTool()) == "jsapiscan" {
		machine := []evidence.Candidate{}
		for _, candidate := range candidates {
			if candidate.Format == "log" {
				candidate.Kind = "log"
				logs = append(logs, candidate)
			} else {
				machine = append(machine, candidate)
			}
		}
		candidates = machine
	}
	report, err := processor.Observe(ctx, recon.Event{Execution: e, Artifacts: candidates, ExpiresAt: e.FinishedAt.Add(24 * time.Hour)})
	if err != nil {
		reason = "offline original registration/parsing failed"
		p.logger.Warn(reason, zap.String("executionId", e.ID), zap.Error(err))
		return
	}
	state, reason = "complete", ""
	for _, candidate := range logs {
		if artifact, logErr := registry.Register(ctx, e, candidate); logErr == nil {
			report.Artifacts = append(report.Artifacts, artifact)
		}
	}
	if len(report.ArtifactErrors) > 0 {
		state, reason = "partial", "one or more originals were rejected or exceeded limits"
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
	if err := p.importRecon(ctx, e, report); err != nil {
		state, reason = "partial", "inventory saved but asset/candidate projection incomplete"
		p.logger.Warn(reason, zap.String("executionId", e.ID), zap.Error(err))
	}
}

func (p *resultPipeline) importRecon(ctx context.Context, e evidence.Execution, report recon.Report) error {
	if e.ProjectID == "" {
		return nil
	}
	principal, authenticated := authctx.PrincipalFromContext(ctx)
	canProject := authenticated && principal.HasPermission("project:write") && p.db.UserCanAccessResource(principal.UserID, principal.ScopeFor("project:write"), "project", e.ProjectID)
	canAsset := authenticated && principal.HasPermission("asset:write") && p.db.UserCanAccessResource(principal.UserID, principal.ScopeFor("asset:write"), "project", e.ProjectID)
	// Page the stored source records, not the bounded model-facing report.
	for _, source := range report.Sources {
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
					if c.Target == "" {
						c.Target = record.Host
					}
					if c.Title == "" {
						c.Title = "scanner match"
					}
					if err := p.db.UpsertFindingCandidate(c); err != nil {
						return err
					}
				}
			}
			if len(assets) > 0 {
				if _, err := p.db.UpsertAssets(assets, e.Owner); err != nil {
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
