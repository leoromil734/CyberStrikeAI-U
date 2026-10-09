package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/multiagent"
	"cyberstrike-ai/internal/tooloutput"

	"go.uber.org/zap"
)

func coverageDecision(valid int, checks ...string) agentfinalizer.Decision {
	return agentfinalizer.Decision{Status: agentfinalizer.StatusInProgress, CompletionReason: agentfinalizer.ReasonCoverageIncomplete, CoverageValidFacts: valid, CoverageProgressKnown: true, MissingChecks: checks}
}

func TestCoverageContinuationProgressAndHardBudget(t *testing.T) {
	state := &finalizationContinuationState{}
	for attempt := 0; attempt < finalizationCoverageMaxAttempts; attempt++ {
		d := coverageDecision(attempt+1, "still incomplete")
		d.CoverageEvidenceExecutions = attempt + 1
		if !observeFinalizationContinuation(d, state) {
			t.Fatalf("real progress stopped at %d: %+v", attempt, state)
		}
		state.recordContinuation(d)
	}
	d := coverageDecision(100, "still incomplete")
	if observeFinalizationContinuation(d, state) {
		t.Fatal("unbounded continuation")
	}
	stopped := finalizationStoppedDecision(d, state)
	if stopped.Status != agentfinalizer.StatusBlocked || stopped.Finalizable || !strings.Contains(strings.Join(stopped.MissingChecks, "\n"), "安全上限") {
		t.Fatalf("budget stop not reported as blocked: %+v", stopped)
	}
}

func TestCoverageContinuationNoProgressAndBrokenManifest(t *testing.T) {
	for _, counts := range [][]int{{20, 20, 20}, {20, 0, 20}, {0, 0, 0}} {
		state := &finalizationContinuationState{}
		for i, count := range counts {
			// A broken manifest can shorten 40 errors to one. It must not be
			// treated as repair; recovering to the old high water is not new progress.
			d := coverageDecision(count, fmt.Sprintf("gap list of size %d", 40-i*19))
			got := observeFinalizationContinuation(d, state)
			if !got {
				t.Fatalf("counts=%v at %d: investigation stopped instead of changing strategy: %+v", counts, i, state)
			}
			state.recordContinuation(d)
		}
		if state.Attempts != 3 || state.StopReason != "" || state.WorkMode != "classify_and_verify" {
			t.Fatalf("stagnant bookkeeping did not switch to investigation: %+v", state)
		}
	}
	state := &finalizationContinuationState{}
	for _, count := range []int{0, 1, 1, 2, 2, 3} {
		d := coverageDecision(count, "gap")
		d.CoverageEvidenceExecutions = count
		if !observeFinalizationContinuation(d, state) {
			t.Fatalf("new independent evidence should reset stagnation: %+v", state)
		}
		state.recordContinuation(d)
	}
}

func TestStoppedFinalizationPreservesOtherTerminalStatesAndResult(t *testing.T) {
	for _, status := range []string{agentfinalizer.StatusFailed, agentfinalizer.StatusCancelled, agentfinalizer.StatusAwaitingHITL} {
		d := agentfinalizer.Decision{Status: status, CompletionReason: status, MissingChecks: []string{"original"}}
		if got := finalizationStoppedDecision(d, &finalizationContinuationState{}); got.Status != status {
			t.Fatalf("changed terminal state: %+v", got)
		}
		if shouldAutoContinueAfterFinalization(d, 0) {
			t.Fatalf("restarted terminal state %s", status)
		}
	}
	passed := agentfinalizer.Decision{Status: agentfinalizer.StatusCompleted, Finalizable: true, Finalized: true}
	if got := finalizationStoppedDecision(passed, &finalizationContinuationState{StopReason: "old failure"}); !got.Finalizable || got.Status != passed.Status || len(got.MissingChecks) != 0 {
		t.Fatalf("success overwritten: %+v", got)
	}
	d := finalizationStoppedDecision(coverageDecision(1, "original"), &finalizationContinuationState{StopReason: "stopped"})
	r := &multiagent.RunResult{Response: "candidate", LastAgentTraceInput: "trace"}
	applyFinalizationDecisionToResult(r, d)
	d.MissingChecks[0] = "mutated"
	if r.Status != agentfinalizer.StatusBlocked || r.Finalized || r.MissingChecks[0] != "original" || r.LastAgentTraceInput != "trace" || r.Response != "candidate" {
		t.Fatalf("result not synchronized safely: %+v", r)
	}
}

func TestCoverageContinuationFeedbackRetainsAllDiagnostics(t *testing.T) {
	checks := make([]string, 25)
	for i := range checks {
		checks[i] = fmt.Sprintf("recon/phase/run-a/%02d: gap", i)
	}
	checks[23] = "recon/js/run-a/ui: invalid YAML js_resource @package/ui " + strings.Repeat("full-detail", 60)
	checks[24] = "recon/source/run-a/fofa/example: incremental 30+ is not an integer"
	inline := formatCoverageContinueMessage(checks)
	if !strings.Contains(inline, checks[23]) || !strings.Contains(inline, checks[24]) {
		t.Fatal("inline fallback silently lost tail/long diagnostics")
	}
	message, path := coverageContinuationMessage(checks, tooloutput.SpillOpts{RootDir: t.TempDir(), ConversationID: "test", ExecutionID: "full-checks.json"})
	if path == "" || !strings.Contains(message, path) || !strings.Contains(message, "read_file") || !strings.Contains(message, "全部缺口") {
		t.Fatalf("missing actionable full feedback: %s", message)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		MissingChecks []string `json:"missingChecks"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if len(artifact.MissingChecks) != len(checks) || artifact.MissingChecks[23] != checks[23] || artifact.MissingChecks[24] != checks[24] {
		t.Fatalf("artifact changed exact diagnostics: %+v", artifact)
	}
	badRoot := filepath.Join(t.TempDir(), "file-not-directory")
	if err := os.WriteFile(badRoot, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	message, path = coverageContinuationMessage(checks, tooloutput.SpillOpts{RootDir: badRoot})
	if path != "" || !strings.Contains(message, checks[24]) || !strings.Contains(message, checks[23]) {
		t.Fatal("spill failure must preserve all checks inline")
	}
}

func TestFinalizationContinuationMissingTraceAndCancellation(t *testing.T) {
	d := coverageDecision(1, "original gap")
	for _, trace := range []string{"", "[]", "not JSON"} {
		state := &finalizationContinuationState{}
		h := &AgentHandler{}
		var history []agent.ChatMessage
		message := "original user input"
		if h.tryAutoContinueAfterFinalization(context.Background(), "test", &multiagent.RunResult{LastAgentTraceInput: trace}, d, state, &history, &message, nil) {
			t.Fatal("continued without usable trace/db")
		}
		if state.Attempts != 0 || state.StopReason == "" || message != "original user input" {
			t.Fatalf("failed restoration consumed/mutated run state: %+v %q", state, message)
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrTaskCancelled)
	state := &finalizationContinuationState{}
	if !stopFinalizationForContext(ctx, state) {
		t.Fatal("cancelled context ignored")
	}
	if got := finalizationStoppedDecision(d, state); got.Status != agentfinalizer.StatusCancelled {
		t.Fatalf("user cancellation not preserved: %+v", got)
	}
}

func TestClassifyAndVerifyPromptOmitsLedgerDispositionQueue(t *testing.T) {
	d := coverageDecision(39,
		"independent discovery inventory: total=36, mapped=0, unresolved=36; raw candidates are not confirmed business test units",
		"independent endpoint inventory group discovery-04a0f71afdf5e8cace9e61fc3f07a5f3 has no matching ledger disposition (owner/scope proof binding missing or different; original retained)",
		"recon/source/run-a/amass/example.test: source claim has no matching actual execution/original with the required completeness",
	)
	d.CoverageInventoryGroups = 36
	d.CoverageUnresolvedGroups = 36
	d.CoverageEvidenceExecutions = 8
	message := classifyAndVerifyContinuationMessage(d)
	// 台账补写引导必须消失；库存查询（query_recon_inventory）允许出现在“挑选高价值
	// URL 实测”的语境里——它服务于实际测试目标选择，不是逐条处置台账修复。
	for _, banned := range []string{"discovery-04a0f71", "coverage-checks-", "has no matching ledger disposition"} {
		if strings.Contains(message, banned) {
			t.Fatalf("classify prompt still queues ledger repair via %q: %s", banned, message)
		}
	}
	if !strings.Contains(message, "优先对已发现的高价值面继续做实际验证，不补台账") || !strings.Contains(message, "source claim") || !strings.Contains(message, "未处置 36 组") || !strings.Contains(message, "不要重复执行已经跑过的侦察工具") {
		t.Fatalf("classify prompt lost the real check, the uncovered total or the source-repair guardrail: %s", message)
	}
	if !strings.Contains(message, "由你判断哪些历史 URL 值得测试") || !strings.Contains(message, "静态资源跳过") || !strings.Contains(message, "query_recon_inventory") {
		t.Fatalf("classify prompt lost the high-value URL selection guidance: %s", message)
	}
	if !strings.Contains(message, "禁止重复空转") || !strings.Contains(message, "一律不得再跑第二次") {
		t.Fatalf("classify prompt lost the repeat-spin guardrail: %s", message)
	}
}

func TestFinalizationContinuationRestoresTraceAndFullChecks(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "continuation.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conv, err := db.CreateConversation("continuation", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	h := &AgentHandler{db: db, logger: zap.NewNop(), config: &config.Config{MultiAgent: config.MultiAgentConfig{EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{ReductionRootDir: t.TempDir()}}}}
	// Use a cancelled callback after restoration, avoiding a real model call.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &finalizationContinuationState{}
	var history []agent.ChatMessage
	message := "user original"
	result := &multiagent.RunResult{LastAgentTraceInput: `[{"role":"user","content":"preserve exclusions and scope"},{"role":"assistant","content":"candidate"}]`}
	d := coverageDecision(2, "recon/js/run-a/ui: malformed js_resource")
	var artifactPath string
	ok := h.tryAutoContinueAfterFinalization(ctx, conv.ID, result, d, state, &history, &message, func(kind, text string, data interface{}) {
		if kind == "finalization_auto_continue" {
			artifactPath, _ = data.(map[string]interface{})["coverageChecksFile"].(string)
			cancel()
		}
	})
	if artifactPath != "" {
		defer os.Remove(artifactPath)
	}
	if ok || state.Attempts != 1 || len(history) == 0 || history[0].Content != "preserve exclusions and scope" || !strings.Contains(message, "read_file") {
		t.Fatalf("resume state not restored losslessly: ok=%v state=%+v history=%+v message=%q", ok, state, history, message)
	}
	trace, _, err := db.GetAgentTrace(conv.ID)
	if err != nil || trace != result.LastAgentTraceInput {
		t.Fatalf("current trace not saved: %v %q", err, trace)
	}
}
