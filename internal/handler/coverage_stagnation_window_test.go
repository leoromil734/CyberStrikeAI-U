package handler

import (
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
)

// 默认停滞窗口为 60 分钟，段数上限仅作安全兜底。
func TestCoverageStagnationWindowDefaultsToSixtyMinutes(t *testing.T) {
	s := &finalizationContinuationState{}
	s.applyContinuationPolicy(nil)
	if s.stagnationWindow() != 60*time.Minute {
		t.Fatalf("default stagnation window = %v, want 60m", s.stagnationWindow())
	}
	if s.coverageMaxSegments() != config.DefaultCoverageContinuationMaxSegments {
		t.Fatalf("default segment guard = %d, want %d", s.coverageMaxSegments(), config.DefaultCoverageContinuationMaxSegments)
	}
}

// 配置可覆盖停滞窗口与段数上限；窗口到点才停止。
func TestCoverageStagnationWindowHonorsConfigOverride(t *testing.T) {
	cfg := &config.Config{MultiAgent: config.MultiAgentConfig{EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{
		CoverageContinuationStagnationMinutes: 30,
		CoverageContinuationMaxSegments:       100,
	}}}
	s := &finalizationContinuationState{}
	s.applyContinuationPolicy(cfg)
	if s.stagnationWindow() != 30*time.Minute {
		t.Fatalf("configured window = %v, want 30m", s.stagnationWindow())
	}
	if s.coverageMaxSegments() != 100 {
		t.Fatalf("configured segment guard = %d, want 100", s.coverageMaxSegments())
	}

	base := time.Now()
	d := coverageDecision(1, "gap")
	d.CoverageEvidenceExecutions = 3
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("first observation stopped early")
	}
	s.recordContinuation(d)
	if !observeFinalizationContinuationAt(d, s, base.Add(29*time.Minute)) {
		t.Fatal("configured window stopped too early")
	}
	s.recordContinuation(d)
	if observeFinalizationContinuationAt(d, s, base.Add(30*time.Minute)) {
		t.Fatal("configured window did not stop at boundary")
	}
	if !strings.Contains(s.StopReason, "30 分钟") {
		t.Fatalf("stop reason lost configured window: %q", s.StopReason)
	}
}

// "新的测试脆弱面"信号：独立候选库存增长会重置停滞时钟。
func TestCoverageInventoryGrowthRenewsStagnationClock(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "gap")
	d.CoverageInventoryGroups = 100
	d.CoverageUnresolvedGroups = 100
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("first observation stopped early")
	}
	s.recordContinuation(d)
	grown := d
	grown.CoverageInventoryGroups = 140
	grown.CoverageUnresolvedGroups = 140
	if !observeFinalizationContinuationAt(grown, s, base.Add(59*time.Minute)) || s.CoverageNoProgress != 0 {
		t.Fatalf("new test surface did not renew the clock: %+v", s)
	}
	s.recordContinuation(d)
	// 无库存增长时 90 分钟已超过原 60 分钟窗口；新进展重置时钟后仍可继续。
	if !observeFinalizationContinuationAt(grown, s, base.Add(90*time.Minute)) {
		t.Fatalf("renewed clock stopped too early: %+v", s)
	}
}

// 库存不可信（CoverageProgressKnown=false）时，库存增长不得用于续期。
func TestUnknownInventoryCannotRenewStagnationClock(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "gap")
	d.CoverageProgressKnown = false
	d.CoverageInventoryGroups = 100
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("first observation stopped early")
	}
	s.recordContinuation(d)
	grown := d
	grown.CoverageInventoryGroups = 200
	if !observeFinalizationContinuationAt(grown, s, base.Add(59*time.Minute)) {
		t.Fatal("unknown inventory stopped early")
	}
	s.recordContinuation(d)
	if observeFinalizationContinuationAt(grown, s, base.Add(60*time.Minute)) {
		t.Fatal("unknown inventory must not renew the stagnation clock")
	}
}

// 回归护栏：有真实进展的快段不会被空转刹车误杀（每段都有新证据 → idle 始终清零）。
func TestWorkingFastSegmentsAreNeverBrakeStopped(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	for i := 0; i < 60; i++ {
		d := coverageDecision(1, "gap")
		d.CoverageEvidenceExecutions = i + 1 // 每段都有新的可核查执行
		at := base.Add(time.Duration(i) * time.Minute)
		if !observeFinalizationContinuationAt(d, s, at) {
			t.Fatalf("working segment %d stopped inside the window: %+v", i, s)
		}
		s.recordContinuation(d)
	}
	if s.WorkAttempts != 60 || s.IdleSegments != 0 {
		t.Fatalf("working segments counted as idle: %+v", s)
	}
}

// Loop 修复回归：秒级 exit 循环（快速空转段）连续达到阈值立即刹车，不等 60 分钟时间窗。
func TestRapidIdleExitStormStopsAfterConsecutiveIdleSegments(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "gap")
	d.CoverageRepairBlocked = true
	d.CoverageEvidenceExecutions = 3 // 首段有真实证据；后续段无任何进展、段长 30 秒
	stoppedAt := -1
	for i := 0; i <= defaultIdleSegmentLimit+1; i++ {
		at := base.Add(time.Duration(i*30) * time.Second)
		if observeFinalizationContinuationAt(d, s, at) {
			s.recordContinuation(d)
			continue
		}
		stoppedAt = i
		break
	}
	if stoppedAt != defaultIdleSegmentLimit {
		t.Fatalf("idle brake fired at observation %d, want %d; state=%+v", stoppedAt, defaultIdleSegmentLimit, s)
	}
	if !strings.Contains(s.StopReason, "快速空转") || !strings.Contains(s.StopReason, "退出-重启循环") {
		t.Fatalf("stop reason lost idle-storm semantics: %q", s.StopReason)
	}
}

// 段时长达到阈值（模型仍在实质执行）时不计为空转，由 60 分钟时间窗兜底。
func TestSlowSegmentsResetIdleBrake(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "gap")
	for i := 0; i < 6; i++ {
		at := base.Add(time.Duration(i*5) * time.Minute) // 每段 5 分钟，超过快速空转判定线
		if !observeFinalizationContinuationAt(d, s, at) {
			t.Fatalf("slow working segment %d stopped early: %+v", i, s)
		}
		s.recordContinuation(d)
	}
	if s.IdleSegments != 0 {
		t.Fatalf("slow segments counted as idle: %+v", s)
	}
}

// 真实进展会清零连续空转计数。
func TestProgressResetsIdleSegments(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "gap")
	d.CoverageEvidenceExecutions = 1
	if !observeFinalizationContinuationAt(d, s, base) {
		t.Fatal("first observation stopped early")
	}
	s.recordContinuation(d)
	for i := 1; i <= 2; i++ {
		if !observeFinalizationContinuationAt(d, s, base.Add(time.Duration(i*30)*time.Second)) {
			t.Fatalf("idle segment %d stopped early: %+v", i, s)
		}
		s.recordContinuation(d)
	}
	if s.IdleSegments != 2 {
		t.Fatalf("idle count = %d, want 2", s.IdleSegments)
	}
	advanced := d
	advanced.CoverageEvidenceExecutions = 2
	if !observeFinalizationContinuationAt(advanced, s, base.Add(100*time.Second)) || s.IdleSegments != 0 {
		t.Fatalf("progress did not reset idle segments: %+v", s)
	}
}

// 空转段的续跑间隔指数增长（5s → 10s → 20s → …），有进展时回落。
func TestContinuationBackoffGrowsWithIdleSegments(t *testing.T) {
	s := &finalizationContinuationState{Attempts: 1}
	base := finalizationContinuationBackoff(s)
	if base > time.Second {
		t.Fatalf("base backoff unexpectedly large: %v", base)
	}
	s.IdleSegments = 2
	b2 := finalizationContinuationBackoff(s)
	s.IdleSegments = 4
	b4 := finalizationContinuationBackoff(s)
	if b2 < 5*time.Second || b4 <= b2 || b4 > 5*time.Minute {
		t.Fatalf("idle backoff not growing: base=%v b2=%v b4=%v", base, b2, b4)
	}
	s.IdleSegments = 0
	if got := finalizationContinuationBackoff(s); got != base {
		t.Fatalf("backoff did not fall back after progress: %v", got)
	}
}

func TestStagnationDurationFormatting(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{90 * time.Minute, "1 小时 30 分钟"},
		{2 * time.Hour, "2 小时"},
		{45 * time.Minute, "45 分钟"},
		{0, "0 分钟"},
		{30 * time.Second, "0 分钟"},
	}
	for _, tc := range cases {
		if got := formatStagnationDuration(tc.d); got != tc.want {
			t.Fatalf("formatStagnationDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
