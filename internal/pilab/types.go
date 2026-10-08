// Package pilab is an opt-in PI experiment runtime. It deliberately has no
// dependency on the production agent, MCP server, database or task scheduler.
package pilab

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound    = errors.New("PI 试验不存在")
	ErrDisabled    = errors.New("PI 实验室尚未启用")
	ErrBusy        = errors.New("PI 实验室已有运行中的试验，请稍后重试")
	ErrStorage     = errors.New("PI 独立存储读写失败，请检查数据目录权限与磁盘空间")
	ErrUnavailable = errors.New("PI 运行时未就绪，请安装独立运行时依赖并检查 Node 路径")
	ErrPartialExit = errors.New("PI 运行时以部分结果退出")
)

type Limits struct {
	MaxParallel    int `json:"max_parallel"`
	MaxAgents      int `json:"max_agents"`
	TimeoutSeconds int `json:"timeout_seconds"`
	MaxRequests    int `json:"max_requests"`
}

var DefaultLimits = Limits{MaxParallel: 2, MaxAgents: 6, TimeoutSeconds: 900, MaxRequests: 80}

type CreateRequest struct {
	Title          string   `json:"title"`
	Prompt         string   `json:"prompt"`
	Scope          []string `json:"scope"`
	AIChannel      string   `json:"ai_channel"`
	MaxParallel    int      `json:"max_parallel"`
	MaxAgents      int      `json:"max_agents"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Authorized     bool     `json:"authorized"`
}

// Model is sent only over the child's stdin; it must never enter storedRun.
type Model struct {
	Provider      string `json:"provider"`
	BaseURL       string `json:"base_url"`
	APIKey        string `json:"api_key"`
	ID            string `json:"id"`
	ContextWindow int    `json:"context_window"`
	MaxTokens     int    `json:"max_tokens"`
}

type Agent struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Task     string `json:"task"`
	ParentID string `json:"parent_id,omitempty"`
	Status   string `json:"status"`
	Summary  string `json:"summary,omitempty"`
}

type Node struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Detail   string `json:"detail"`
	Status   string `json:"status"`
	URL      string `json:"url,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

type Edge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	URL         string `json:"url"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

type Run struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Prompt     string    `json:"prompt"`
	Scope      []string  `json:"scope"`
	AIChannel  string    `json:"ai_channel"`
	Model      string    `json:"model"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Error      string    `json:"error,omitempty"`
	Report     string    `json:"report"`
	Limits     Limits    `json:"limits"`
	Agents     []Agent   `json:"agents"`
	Nodes      []Node    `json:"nodes"`
	Edges      []Edge    `json:"edges"`
	Findings   []Finding `json:"findings"`
	EventCount int64     `json:"event_count"`
}

type Event struct {
	Seq     int64           `json:"seq"`
	Time    time.Time       `json:"time"`
	Type    string          `json:"type"`
	AgentID string          `json:"agent_id,omitempty"`
	Data    json.RawMessage `json:"data"`
}

type EventPage struct {
	Events  []Event `json:"events"`
	Cursor  int64   `json:"cursor"`
	HasMore bool    `json:"has_more"`
}

type Status struct {
	Enabled   bool     `json:"enabled"`
	Ready     bool     `json:"ready"`
	Reason    string   `json:"reason"`
	Runtime   string   `json:"runtime"`
	Limits    Limits   `json:"limits"`
	Tools     []string `json:"tools"`
	Isolation string   `json:"isolation"`
}

type Input struct {
	RunID  string   `json:"run_id"`
	Prompt string   `json:"prompt"`
	Scope  []string `json:"scope"`
	Limits Limits   `json:"limits"`
	Model  Model    `json:"model"`
}

// Runtime permits hermetic tests without invoking a model or probing a target.
type Runtime interface {
	Check(context.Context) error
	Run(context.Context, string, Input, func(Event) error) error
}

func active(status string) bool { return status == "queued" || status == "running" }
