package pilab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxRuns = 1000
const maxEvents = 2000
const maxEventLogBytes = 8 * 1024 * 1024

type Options struct {
	Enabled bool
	Root    string
	Runtime Runtime
}

type storedRun struct {
	Run
	OwnerID    string `json:"owner_id"`
	EventBytes int64  `json:"event_bytes"`
}

type Manager struct {
	mu      sync.Mutex
	options Options
	loaded  bool
	closed  bool
	runs    map[string]*storedRun
	cancels map[string]context.CancelFunc
	wg      sync.WaitGroup
}

// New creates no directories, starts no goroutines and makes no network requests.
func New(options Options) *Manager {
	return &Manager{options: options, runs: map[string]*storedRun{}, cancels: map[string]context.CancelFunc{}}
}

func (m *Manager) Status(ctx context.Context) Status {
	status := Status{Enabled: m.options.Enabled, Runtime: "pi-coding-agent", Limits: Limits{MaxParallel: 4, MaxAgents: 12, TimeoutSeconds: 1800, MaxRequests: DefaultLimits.MaxRequests},
		Tools:     []string{"delegate_agents", "inspect_http", "record_surface", "record_finding"},
		Isolation: "独立 PI 进程、记录和预算；仅公网授权来源及需求明示 URL 的 GET/HEAD 和响应头/哈希观察，无 Shell、现有 MCP 或生产任务联动；不是操作系统安全沙箱"}
	if !m.options.Enabled {
		status.Reason = "默认关闭；安装 runtimes/pi-lab 依赖后，由管理员在下次计划启动时设置 CYBERSTRIKE_PI_ENABLED=true"
		return status
	}
	if m.options.Runtime == nil || m.options.Runtime.Check(ctx) != nil {
		status.Reason = ErrUnavailable.Error()
		return status
	}
	status.Ready = true
	return status
}

func (m *Manager) Create(owner string, req CreateRequest, model Model) (Run, error) {
	if !m.options.Enabled {
		return Run{}, ErrDisabled
	}
	if strings.TrimSpace(owner) == "" {
		return Run{}, ErrNotFound
	}
	req, limits, err := ValidateRequest(req)
	if err != nil {
		return Run{}, err
	}
	model = NormalizeModel(model)
	if err = ValidateModel(model); err != nil {
		return Run{}, err
	}
	// No credentials appear in readiness checks or command-line arguments.
	if !m.Status(context.Background()).Ready {
		return Run{}, ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Run{}, ErrDisabled
	}
	if err := m.loadLocked(); err != nil {
		return Run{}, err
	}
	if len(m.cancels) != 0 {
		return Run{}, ErrBusy
	}
	if len(m.runs) >= maxRuns {
		return Run{}, fmt.Errorf("PI 试验记录已达 1000 条，请先由管理员离线归档独立数据目录")
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	run := &storedRun{OwnerID: owner, Run: Run{ID: id, Title: req.Title, Prompt: req.Prompt, Scope: req.Scope,
		AIChannel: req.AIChannel, Model: model.ID, Status: "queued", Limits: limits, CreatedAt: now, UpdatedAt: now,
		Agents: []Agent{}, Nodes: []Node{}, Edges: []Edge{}, Findings: []Finding{}}}
	workdir := filepath.Join(m.options.Root, "runs", id, "workspace")
	if err := os.MkdirAll(workdir, 0700); err != nil {
		return Run{}, ErrStorage
	}
	if err := m.saveLocked(run); err != nil {
		return Run{}, err
	}
	m.runs[id] = run
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(limits.TimeoutSeconds)*time.Second)
	m.cancels[id] = cancel
	input := Input{RunID: id, Prompt: req.Prompt, Scope: append([]string{}, req.Scope...), Limits: limits, Model: model}
	result := cloneRun(run.Run)
	m.wg.Add(1)
	go m.execute(ctx, cancel, workdir, input)
	return result, nil
}

func (m *Manager) execute(ctx context.Context, cancel context.CancelFunc, workdir string, input Input) {
	defer m.wg.Done()
	defer cancel()
	m.mu.Lock()
	run := m.runs[input.RunID]
	if !active(run.Status) {
		delete(m.cancels, input.RunID)
		m.mu.Unlock()
		return
	}
	run.Status, run.UpdatedAt = "running", time.Now().UTC()
	err := m.saveLocked(run)
	m.mu.Unlock()
	completeStatus := ""
	if err == nil {
		err = m.options.Runtime.Run(ctx, workdir, input, func(event Event) error {
			clean, err := redactEvent(event, input.Model.APIKey)
			if err != nil {
				return err
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			if !active(run.Status) || ctx.Err() != nil {
				return context.Canceled
			}
			if completeStatus != "" {
				return fmt.Errorf("PI 在终止事件后继续输出，协议无效")
			}
			if err := projectEvent(&run.Run, clean); err != nil {
				return err
			}
			if clean.Type == "complete" {
				var result struct {
					Status string `json:"status"`
				}
				_ = json.Unmarshal(clean.Data, &result)
				if result.Status != "completed" && result.Status != "partial" {
					return fmt.Errorf("PI 终止状态无效")
				}
				completeStatus = result.Status
			}
			return m.appendLocked(run, clean)
		})
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cancels, input.RunID)
	if !active(run.Status) {
		return
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		run.Status, run.Error = "partial", "达到独立试验时限；已保留当前证据，尚未完成全部测试"
	case ctx.Err() != nil:
		run.Status, run.Error = "interrupted", "PI 运行被中断"
	case errors.Is(err, ErrPartialExit) && completeStatus == "partial" && strings.TrimSpace(run.Report) != "":
		run.Status = "partial"
		if run.Error == "" {
			run.Error = "PI 返回了受限或未完成的结果；请查看报告中的限制说明"
		}
	case err != nil:
		run.Status = "failed"
		// Runner errors may contain provider text; expose only locally generated diagnostics.
		run.Error = "PI 运行失败，已保留已接收事件。请检查运行时、模型兼容性、预算及独立数据目录"
	case completeStatus == "" || strings.TrimSpace(run.Report) == "":
		run.Status, run.Error = "failed", "PI 未返回完整的终止事件和报告，不能视为成功"
	case completeStatus == "completed" && !agentsCompleted(&run.Run):
		run.Status, run.Error = "failed", "PI 未返回协调 Agent 和已派发 Agent 的完整完成状态"
	default:
		run.Status = completeStatus
		if run.Error != "" && run.Status == "completed" {
			run.Status = "partial"
		}
	}
	finishAgents(&run.Run)
	run.UpdatedAt = time.Now().UTC()
	if m.saveLocked(run) != nil {
		run.Status, run.Error = "failed", ErrStorage.Error()
	}
}

func agentsCompleted(run *Run) bool {
	coordinator := false
	for _, agent := range run.Agents {
		if agent.Status != "completed" {
			return false
		}
		if agent.ID == "coordinator" {
			coordinator = true
		}
	}
	return coordinator
}

func finishAgents(run *Run) {
	for i := range run.Nodes {
		if run.Nodes[i].Kind == "agent" && active(run.Nodes[i].Status) {
			run.Nodes[i].Status = "interrupted"
			if run.Status == "cancelled" {
				run.Nodes[i].Status = "cancelled"
			}
		}
	}
	for i := range run.Agents {
		if active(run.Agents[i].Status) {
			// No agent_end means we cannot assert successful completion.
			run.Agents[i].Status = "interrupted"
			if run.Status == "cancelled" {
				run.Agents[i].Status = "cancelled"
			}
		}
	}
}

func (m *Manager) List(owner string) ([]Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadLocked(); err != nil {
		return nil, err
	}
	result := []Run{}
	for _, run := range m.runs {
		if run.OwnerID == owner {
			result = append(result, cloneRun(run.Run))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	// The list is a lightweight index; full evidence is returned by Get.
	if len(result) > 100 {
		result = result[:100]
	}
	for i := range result {
		result[i].Agents = []Agent{}
		result[i].Nodes = []Node{}
		result[i].Edges = []Edge{}
		result[i].Findings = []Finding{}
		result[i].Report = ""
		result[i].Prompt = ""
	}
	return result, nil
}

func (m *Manager) ownedLocked(owner, id string) (*storedRun, error) {
	if err := m.loadLocked(); err != nil {
		return nil, err
	}
	run, ok := m.runs[id]
	if !ok || owner == "" || run.OwnerID != owner {
		return nil, ErrNotFound
	}
	return run, nil
}

func (m *Manager) Get(owner, id string) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, err := m.ownedLocked(owner, id)
	if err != nil {
		return Run{}, err
	}
	return cloneRun(run.Run), nil
}

func (m *Manager) Cancel(owner, id string) (Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, err := m.ownedLocked(owner, id)
	if err != nil {
		return Run{}, err
	}
	if active(run.Status) {
		run.Status, run.UpdatedAt = "cancelled", time.Now().UTC()
		finishAgents(&run.Run)
		if cancel := m.cancels[id]; cancel != nil {
			cancel()
		}
		if err := m.saveLocked(run); err != nil {
			return Run{}, err
		}
	}
	return cloneRun(run.Run), nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	for id, cancel := range m.cancels {
		run := m.runs[id]
		if active(run.Status) {
			run.Status = "interrupted"
			run.Error = "服务关闭，PI 试验不会自动恢复执行"
			run.UpdatedAt = time.Now().UTC()
			finishAgents(&run.Run)
			_ = m.saveLocked(run)
		}
		cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func cloneRun(run Run) Run {
	run.Scope = append([]string{}, run.Scope...)
	run.Agents = append([]Agent{}, run.Agents...)
	run.Nodes = append([]Node{}, run.Nodes...)
	run.Edges = append([]Edge{}, run.Edges...)
	run.Findings = append([]Finding{}, run.Findings...)
	return run
}
