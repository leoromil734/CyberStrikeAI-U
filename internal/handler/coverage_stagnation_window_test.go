package handler

import (
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/config"
)

// Loop Engineering 回归护栏：默认停滞窗口为 90 分钟，段数上限仅作安全兜底。
func TestCoverageStagnationWindowDefaultsToNinetyMinutes(t *testing.T) {
	s := &finalizationContinuationState{}
	s.applyContinuationPolicy(nil)
	if s.stagnationWindow() != 90*time.Minute {
		t.Fatalf("default stagnation window = %v, want 90m", s.stagnationWindow())
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
	if !observeFinalizationContinuationAt(grown, s, base.Add(89*time.Minute)) || s.CoverageNoProgress != 0 {
		t.Fatalf("new test surface did not renew the clock: %+v", s)
	}
	s.recordContinuation(d)
	// 若无库存增长，120 分钟已超原 90 分钟窗口；因为时钟被新面重置，仍可继续。
	if !observeFinalizationContinuationAt(grown, s, base.Add(120*time.Minute)) {
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
	if !observeFinalizationContinuationAt(grown, s, base.Add(89*time.Minute)) {
		t.Fatal("unknown inventory stopped early")
	}
	s.recordContinuation(d)
	if observeFinalizationContinuationAt(grown, s, base.Add(90*time.Minute)) {
		t.Fatal("unknown inventory must not renew the stagnation clock")
	}
}

// 回归护栏：窗口内跑大量快段也不会像旧版「连续 3 段」那样提前停止。
func TestFastSegmentsInsideWindowNeverStopLikeLegacyThreeSegmentRule(t *testing.T) {
	s := &finalizationContinuationState{}
	base := time.Now()
	d := coverageDecision(1, "gap")
	d.CoverageEvidenceExecutions = 5
	for i := 0; i < 60; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		if !observeFinalizationContinuationAt(d, s, at) {
			t.Fatalf("fast segment %d stopped inside the 90m window: %+v", i, s)
		}
		s.recordContinuation(d)
	}
	if s.WorkAttempts != 60 {
		t.Fatalf("expected 60 work segments, got %d", s.WorkAttempts)
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
