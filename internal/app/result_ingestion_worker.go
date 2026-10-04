package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
	"go.uber.org/zap"
)

const (
	resultIngestionLease   = 3 * time.Minute
	resultIngestionPoll    = time.Second
	resultIngestionTimeout = 2 * time.Minute
)

func offlineResultPipeline(db *database.DB, cfg *config.Config, logger *zap.Logger) *resultPipeline {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &resultPipeline{db: db, root: cfg.MultiAgent.EinoMiddleware.ReductionRootDir, logger: logger, wake: make(chan struct{}, 1)}
}

func (p *resultPipeline) worker(ctx context.Context) {
	ticker := time.NewTicker(resultIngestionPoll)
	defer ticker.Stop()
	for ctx.Err() == nil {
		job, err := p.db.ClaimResultIngestion(ctx, "", resultIngestionLease)
		if err == nil && job != nil {
			if err = p.runClaim(ctx, *job); err != nil {
				p.logger.Warn("原件处理领取已失效或状态保存失败", zap.String("executionId", job.ExecutionID), zap.Error(err))
			}
			continue
		}
		if err != nil && ctx.Err() == nil {
			p.logger.Warn("读取持久化原件队列失败", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
	}
}

func (p *resultPipeline) ingestionProjection(ctx context.Context, e evidence.Execution) database.ResultIngestionProjection {
	principal, ok := authctx.PrincipalFromContext(ctx)
	if !ok || principal.UserID != e.Owner {
		return database.ResultIngestionProjection{}
	}
	canWrite := func(permission string) bool {
		return e.ProjectID != "" && principal.HasPermission(permission) && validIngestionScope(principal.ScopeFor(permission)) &&
			p.db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), "project", e.ProjectID)
	}
	return database.ResultIngestionProjection{Owner: e.Owner,
		ProjectWrite: canWrite("project:write"), ProjectScope: principal.ScopeFor("project:write"),
		AssetWrite: canWrite("asset:write"), AssetScope: principal.ScopeFor("asset:write")}
}

// Replay never inherits an operator/admin principal from the caller. A legacy
// row has no historical authorization snapshot and therefore gets no projection
// permissions, even if its owner happens to be an administrator today.
func (p *resultPipeline) ingestionContext(ctx context.Context, s database.ResultIngestionSnapshot) (context.Context, bool) {
	e, grant := s.Execution, s.Projection
	permissions, scopes := map[string]bool{}, map[string]string{}
	if grant.Owner == e.Owner && e.ProjectID != "" {
		current, err := p.db.ResolveRBACAccess(e.Owner)
		if err == nil && current.User.Enabled {
			for _, perm := range []struct {
				key, scope string
				allowed    bool
			}{{"project:write", grant.ProjectScope, grant.ProjectWrite}, {"asset:write", grant.AssetScope, grant.AssetWrite}} {
				liveScope := current.PermissionScopes[perm.key]
				// Check each permission scope separately. Taking a maximum across
				// unrelated roles would silently widen the historical authority.
				if perm.allowed && validIngestionScope(perm.scope) && validIngestionScope(liveScope) && current.Permissions[perm.key] &&
					p.db.UserCanAccessResource(e.Owner, perm.scope, "project", e.ProjectID) &&
					p.db.UserCanAccessResource(e.Owner, liveScope, "project", e.ProjectID) {
					permissions[perm.key] = true
					scopes[perm.key] = perm.scope
				}
			}
		}
	}
	ctx = authctx.WithPrincipal(ctx, authctx.NewPrincipalWithScopes(e.Owner, "", "", permissions, scopes))
	ctx = evidence.WithAccess(ctx, e.Access)
	return ctx, e.ProjectID != "" && len(permissions) == 0
}

func validIngestionScope(s string) bool {
	return s == database.RBACScopeOwn || s == database.RBACScopeAssigned || s == database.RBACScopeAll
}

type ingestionClaimContextKey struct{}

func checkIngestionClaim(ctx context.Context, db *database.DB) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if job, ok := ctx.Value(ingestionClaimContextKey{}).(database.ResultIngestionJob); ok {
		return db.CheckResultIngestionLease(ctx, job)
	}
	return nil // Explicit artifact registration has its own authorization path.
}

// All writes use the immutable snapshot/binding and deterministic import keys.
// Checking the lease before each store mutation also stops cancelled/expired
// workers from continuing a long parse/import. Final job state is always an
// atomic DB compare-and-swap, rather than a context-only check.
type ingestionStore struct {
	*database.DB
}

func (s ingestionStore) RecordExecution(ctx context.Context, e evidence.Execution) error {
	if err := checkIngestionClaim(ctx, s.DB); err != nil {
		return err
	}
	return s.DB.RecordExecution(ctx, e)
}
func (s ingestionStore) RegisterArtifact(ctx context.Context, a evidence.VerifiedArtifact) (evidence.Artifact, error) {
	if err := checkIngestionClaim(ctx, s.DB); err != nil {
		return evidence.Artifact{}, err
	}
	return s.DB.RegisterArtifact(ctx, a)
}
func (s ingestionStore) ImportReconSource(ctx context.Context, source recon.Source, records []recon.Record) (recon.ImportResult, error) {
	if err := checkIngestionClaim(ctx, s.DB); err != nil {
		return recon.ImportResult{}, err
	}
	return s.DB.ImportReconSource(ctx, source, records)
}

func (p *resultPipeline) runClaim(parent context.Context, job database.ResultIngestionJob) (finishErr error) {
	ctx, cancel := context.WithTimeout(parent, resultIngestionTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, ingestionClaimContextKey{}, job)
	state, reason, retryable := "failed", "offline ingestion panic; original retained", true
	var processingErr error
	// A stopped heartbeat is joined before finalizing, so it cannot extend an
	// already completed/requeued job. A failed finish leaves the lease to expire.
	heartbeatDone := make(chan struct{})
	leaseCtx := ctx
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				renewCtx, stop := context.WithTimeout(leaseCtx, 5*time.Second)
				err := p.db.RenewResultIngestionLease(renewCtx, job, resultIngestionLease)
				stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			state, reason = "failed", "offline ingestion panic; original retained"
			p.logger.Error(reason, zap.String("executionId", job.ExecutionID))
		}
		cancel()
		<-heartbeatDone
		if processingErr != nil {
			p.logger.Warn(reason, zap.String("executionId", job.ExecutionID), zap.Int("attempt", job.Attempts), zap.Error(processingErr))
			// Do not persist raw errors: driver/file errors may include secret
			// arguments or paths. Stable reason + error class remain diagnosable.
			reason += "; error_class=" + ingestionErrorClass(processingErr)
			retryable = !errors.Is(processingErr, evidence.ErrDenied) && !errors.Is(processingErr, evidence.ErrChanged) && !errors.Is(processingErr, evidence.ErrUnsafePath) && !errors.Is(processingErr, evidence.ErrLimit) && !errors.Is(processingErr, sql.ErrNoRows)
		}
		finishCtx, stop := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
		defer stop()
		finishErr = p.db.FinishResultIngestion(finishCtx, job, state, reason, retryable)
	}()
	snapshot, err := p.db.LoadResultIngestionSnapshot(ctx, job)
	if err != nil {
		reason, processingErr = "trusted saved result snapshot unavailable or inconsistent", err
		return nil
	}
	ctx, projectionSkipped := p.ingestionContext(ctx, snapshot)
	state, reason, processingErr = p.process(ctx, snapshot.Execution, snapshot.Original)
	if projectionSkipped && state != "failed" {
		if reason != "" {
			reason += "; "
		}
		reason += "asset/candidate projection skipped: historical/current authorization unavailable"
	}
	return nil
}

func ingestionErrorClass(err error) string {
	switch {
	case errors.Is(err, evidence.ErrDenied):
		return "binding_denied"
	case errors.Is(err, evidence.ErrChanged):
		return "original_changed"
	case errors.Is(err, evidence.ErrUnsafePath):
		return "unsafe_original"
	case errors.Is(err, evidence.ErrLimit):
		return "limit_exceeded"
	case errors.Is(err, database.ErrResultIngestionLeaseLost):
		return "lease_lost"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, sql.ErrNoRows):
		return "saved_result_missing"
	default:
		return "storage_or_parse_error"
	}
}

// ResultIngestionReplayResult reports the actual stored state, not an assumed
// success after queueing. Pending plus Error means the caller stopped waiting;
// its durable job can still be resumed by the normal worker or a later replay.
type ResultIngestionReplayResult struct {
	database.ResultIngestionJob
	Requeued bool   `json:"requeued"`
	Error    string `json:"error,omitempty"`
}

// ReplayResultIngestions is a trusted, local maintenance entry point. It starts
// no Web service, scheduler, MCP server, tool command or network client. Only the
// supplied IDs are requeued/claimed, one at a time, using saved result snapshots.
// Use the same reduction root/filesystem as the original execution. No IDs means
// no work, never "all failures". Returned reports include every unique input ID;
// callers should print them even when the aggregate error is non-nil.
func ReplayResultIngestions(ctx context.Context, db *database.DB, cfg *config.Config, logger *zap.Logger, ids []string) ([]ResultIngestionReplayResult, error) {
	if db == nil || cfg == nil || ctx == nil || len(ids) > 1000 {
		return nil, errors.New("replay requires context, database, config and at most 1000 explicit execution IDs")
	}
	if len(ids) == 0 {
		return []ResultIngestionReplayResult{}, nil
	}
	if err := db.InitResultIngestionTables(); err != nil {
		return nil, err
	}
	p := offlineResultPipeline(db, cfg, logger)
	reports := make([]ResultIngestionReplayResult, 0, len(ids))
	seen := map[string]bool{}
	var allErrors error
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		report := ResultIngestionReplayResult{ResultIngestionJob: database.ResultIngestionJob{ResultIngestionState: database.ResultIngestionState{ExecutionID: id, State: "unknown"}}}
		var err error
		if id == "" || strings.TrimSpace(id) != id || len(id) > 256 {
			err = errors.New("invalid explicit execution ID")
		} else {
			report, err = p.replayOne(ctx, id)
		}
		if err != nil {
			report.Error = err.Error()
			allErrors = errors.Join(allErrors, fmt.Errorf("replay %s: %w", id, err))
		}
		reports = append(reports, report)
	}
	return reports, allErrors
}

func (p *resultPipeline) replayOne(ctx context.Context, id string) (report ResultIngestionReplayResult, err error) {
	report.ExecutionID, report.State = id, "unknown"
	job, err := p.db.ResultIngestionJob(ctx, id)
	if err != nil {
		return report, err
	}
	report.ResultIngestionJob = job
	// Refresh state on every exit (including cancellation), without converting a
	// failed processing attempt or a live lease to a synthetic success.
	defer func() {
		readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if final, readErr := p.db.ResultIngestionJob(readCtx, id); readErr == nil {
			report.ResultIngestionJob = final
		} else {
			err = errors.Join(err, readErr)
		}
	}()
	if job.State == "failed" || job.State == "partial" {
		accessCtx := evidence.WithAccess(ctx, job.Access)
		e, loadErr := p.db.ResultExecution(accessCtx, id)
		if loadErr != nil {
			return report, loadErr
		}
		if err = p.db.RequeueResultIngestion(accessCtx, e); err != nil {
			return report, err
		}
		report.Requeued = true
	}
	for {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		job, err = p.db.ResultIngestionJob(ctx, id)
		if err != nil {
			return report, err
		}
		switch job.State {
		case "complete":
			return report, nil
		case "partial", "failed":
			return report, fmt.Errorf("actual final state %s: %s", job.State, job.Reason)
		case "pending":
		default:
			return report, fmt.Errorf("unsupported ingestion state %q", job.State)
		}
		claim, claimErr := p.db.ClaimResultIngestion(ctx, id, resultIngestionLease)
		if claimErr != nil {
			return report, claimErr
		}
		if claim != nil {
			if err = p.runClaim(ctx, *claim); err != nil && !errors.Is(err, database.ErrResultIngestionLeaseLost) {
				return report, err
			}
			continue
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return report, ctx.Err()
		case <-timer.C:
		}
	}
}
