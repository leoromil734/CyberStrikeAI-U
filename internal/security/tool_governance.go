package security

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"
)

type ParameterValidationError struct{ Field, Expected, Problem string }

func (e *ParameterValidationError) Error() string {
	return fmt.Sprintf("参数 %s: %s（期望 %s）", e.Field, e.Problem, e.Expected)
}

func parameterValidationResult(tool string, err error) *mcp.ToolResult {
	payload := map[string]interface{}{"status": "invalid_arguments", "tool": tool, "error": err.Error(), "retryable": false}
	if p, ok := err.(*ParameterValidationError); ok {
		payload["field"] = p.Field
		payload["expected"] = p.Expected
	}
	body, _ := json.Marshal(payload)
	return &mcp.ToolResult{IsError: true, Content: []mcp.Content{{Type: "text", Text: string(body)}}}
}

func numericParameter(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	case json.Number:
		n, err := x.Float64()
		return n, err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return n, err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
	}
	return 0, false // boolean values must never become numeric budgets
}

func (e *Executor) validateToolParameterValues(tool *config.ToolConfig, args map[string]interface{}) error {
	for _, p := range tool.Parameters {
		v := e.getParamValue(args, p)
		if v == nil {
			continue
		}
		bad := func(problem string) error {
			return &ParameterValidationError{Field: p.Name, Expected: p.Type, Problem: problem}
		}
		switch p.Type {
		case "int", "integer", "number", "float", "double":
			n, ok := numericParameter(v)
			if !ok {
				return bad("必须为有限数值，不能传布尔值或非数值文本")
			}
			if (p.Type == "int" || p.Type == "integer") && math.Trunc(n) != n {
				return bad("必须为整数")
			}
			if p.Minimum != nil && n < *p.Minimum {
				return bad(fmt.Sprintf("低于最小值 %g", *p.Minimum))
			}
			if p.Maximum != nil && n > *p.Maximum {
				return bad(fmt.Sprintf("超过最大值 %g", *p.Maximum))
			}
		case "bool", "boolean":
			if _, ok := v.(bool); !ok {
				return bad("必须为 JSON boolean")
			}
		case "string":
			if _, ok := v.(string); !ok {
				return bad("必须为字符串")
			}
		case "array":
			r := reflect.ValueOf(v)
			if r.Kind() != reflect.Array && r.Kind() != reflect.Slice {
				return bad("必须为数组")
			}
			if p.MaxItems != nil && r.Len() > *p.MaxItems {
				return bad(fmt.Sprintf("元素超过上限 %d", *p.MaxItems))
			}
		}
		if len(p.Options) > 0 {
			s, ok := v.(string)
			if !ok {
				return bad("枚举值必须为字符串")
			}
			found := false
			for _, o := range p.Options {
				if o == s {
					found = true
					break
				}
			}
			if !found {
				return bad("合法值: " + strings.Join(p.Options, ", "))
			}
		}
		if s, ok := v.(string); ok && s != "" {
			for _, other := range p.ConflictsWith {
				if supplied, ok := args[other]; ok && supplied != nil && supplied != "" {
					return bad("与 " + other + " 互斥")
				}
			}
		}
	}
	return nil
}

type budgetBucket struct {
	slots chan struct{}
	refs  int
}

// ToolBudget bounds simultaneous executions, not the unobservable number of
// HTTP requests inside an arbitrary process. Buckets span conversations/agents.
type ToolBudget struct {
	global             chan struct{}
	perTool, perTarget int
	mu                 sync.Mutex
	buckets            map[string]*budgetBucket
}

func boundedConcurrency(n, fallback int) int {
	if n <= 0 {
		return fallback
	}
	if n > 256 {
		return 256
	}
	return n
}
func NewToolBudget(cfg *config.SecurityConfig) *ToolBudget {
	g, t, h := 32, 8, 2
	if cfg != nil {
		g = boundedConcurrency(cfg.MaxConcurrentTools, g)
		t = boundedConcurrency(cfg.MaxConcurrentPerTool, t)
		h = boundedConcurrency(cfg.MaxConcurrentPerTarget, h)
	}
	return &ToolBudget{global: make(chan struct{}, g), perTool: t, perTarget: h, buckets: make(map[string]*budgetBucket)}
}

func budgetTargets(args map[string]interface{}) []string {
	set := map[string]bool{}
	for _, key := range []string{"url", "target", "host", "domain", "ip"} {
		value, ok := args[key].(string)
		if !ok {
			continue
		}
		for _, raw := range strings.Split(value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
				continue
			}
			if !strings.Contains(raw, "://") {
				raw = "//" + raw
			}
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			set[strings.ToLower(parsed.Hostname())] = true
		}
	}
	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func (b *ToolBudget) Acquire(ctx context.Context, tool string, targets []string) (func(), error) {
	if b == nil {
		return func() {}, nil
	}
	keys := []string{"tool:" + tool}
	seen := map[string]bool{}
	for _, host := range targets {
		if host != "" && !seen[host] {
			keys = append(keys, "target:"+host)
			seen[host] = true
		}
	}
	sort.Strings(keys)
	b.mu.Lock()
	buckets := make([]*budgetBucket, 0, len(keys))
	for _, key := range keys {
		bucket := b.buckets[key]
		if bucket == nil {
			limit := b.perTarget
			if strings.HasPrefix(key, "tool:") {
				limit = b.perTool
			}
			bucket = &budgetBucket{slots: make(chan struct{}, limit)}
			b.buckets[key] = bucket
		}
		bucket.refs++
		buckets = append(buckets, bucket)
	}
	b.mu.Unlock()
	acquired := []chan struct{}{}
	var once sync.Once
	release := func() {
		once.Do(func() {
			for i := len(acquired) - 1; i >= 0; i-- {
				<-acquired[i]
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			for i, bucket := range buckets {
				bucket.refs--
				if bucket.refs == 0 {
					delete(b.buckets, keys[i])
				}
			}
		})
	}
	for _, slots := range append(func() []chan struct{} {
		out := make([]chan struct{}, 0, len(buckets))
		for _, v := range buckets {
			out = append(out, v.slots)
		}
		return out
	}(), b.global) {
		select {
		case slots <- struct{}{}:
			acquired = append(acquired, slots)
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}
