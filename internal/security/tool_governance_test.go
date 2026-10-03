package security

import (
	"context"
	"cyberstrike-ai/internal/config"
	"testing"
	"time"
)

func TestNumericBudgetsRejectBooleansAndFractions(t *testing.T) {
	e := &Executor{}
	min, max := float64(1), float64(20)
	tool := &config.ToolConfig{Name: "bounded", Parameters: []config.ParameterConfig{{Name: "limit", Type: "int", Minimum: &min, Maximum: &max}}}
	for _, v := range []interface{}{false, true, 0, 21, 1.5} {
		if e.validateToolParameterValues(tool, map[string]interface{}{"limit": v}) == nil {
			t.Fatalf("invalid value accepted: %#v", v)
		}
	}
	for _, v := range []interface{}{1, 20, float64(3), "4"} {
		if err := e.validateToolParameterValues(tool, map[string]interface{}{"limit": v}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSharedToolBudgetCancellationAndIndependentTargets(t *testing.T) {
	b := NewToolBudget(&config.SecurityConfig{MaxConcurrentTools: 2, MaxConcurrentPerTool: 2, MaxConcurrentPerTarget: 1})
	release, err := b.Acquire(context.Background(), "scanner", []string{"one.example"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := b.Acquire(ctx, "scanner", []string{"one.example"}); done <- err }()
	independent, err := b.Acquire(context.Background(), "other", []string{"two.example"})
	if err != nil {
		t.Fatal(err)
	}
	independent()
	if err := <-done; err == nil {
		t.Fatal("same target ignored budget")
	}
	release()
	release() // idempotent release
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buckets) != 0 || len(b.global) != 0 {
		t.Fatal("cancelled admission leaked buckets/tokens")
	}
}

func TestBudgetTargetsNormalizeHostsWithoutDroppingOrigins(t *testing.T) {
	got := budgetTargets(map[string]interface{}{"url": "https://A.example/x,https://b.example:8443/y", "domain": "A.example"})
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Fatalf("wrong target buckets: %v", got)
	}
}
