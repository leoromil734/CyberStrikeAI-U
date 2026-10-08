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

func runEventLimit(run *Run) int64 {
	if run.Mode == ModePlatform {
		return 12000
	}
	return maxEvents
}
func runLogLimit(run *Run) int64 {
	if run.Mode == ModePlatform {
		return 64 * 1024 * 1024
	}
	return maxEventLogBytes
}
func runSnapshotLimit(run *Run) int {
	if run.Mode == ModePlatform {
		return 8 * 1024 * 1024
	}
	return 2 * 1024 * 1024
}

type Options struct {
	Enabled       bool
	Root          string
	Runtime       Runtime
	MaxConcurrent int
}

type storedRun struct {
	Run
	OwnerID    string `json:"owner_id"`
	EventBytes int64  `json:"event_bytes"`
}

type Manager struct {
	mu              sync.Mutex
	options         Options
	loaded          bool
	closed          bool
	runs            map[string]*storedRun
	cancels         map[string]context.CancelFunc
	wg              sync.WaitGroup
	recoverPlatform func(string, *Run) error
}

// New creates no directories, starts no goroutines and makes no network requests.
func New(options Options) *Manager {
	if options.MaxConcurrent < 1 {
		options.MaxConcurrent = 1
	}
	if options.MaxConcurrent > 4 {
		options.MaxConcurrent = 4
	}
	return &Manager{options: options, runs: map[string]*storedRun{}, cancels: map[string]context.CancelFunc{}}
}

// SetRecovery installs a metadata-only restart reconciler. It must never
// resume model execution or replay operational tool calls.
func (m *Manager) SetRecovery(recoverRun func(string, *Run) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoverPlatform = recoverRun
}

func (m *Manager) Status(ctx context.Context) Status {
	status := Status{Enabled: m.options.Enabled, Runtime: "pi-coding-agent", Modes: []string{ModePlatform, ModeProbe}, PlatformLimits: PlatformLimitCaps, Limits: Limits{MaxParallel: 4, MaxAgents: 12, TimeoutSeconds: 1800, MaxRequests: DefaultLimits.MaxRequests, MaxTurns: 20, MaxToolCalls: 256},
		Tools:     []string{"delegate_agents", "inspect_http", "record_surface", "record_finding"},
		Isolation: "平台模式复用现有渗透测试角色、技能、工具权限和项目工作目录；诊断模式保留受限 HTTP 检查。工具实际执行和证据入库由平台控制，不绕过授权，也不宣称任意命令的网络隔离"}
	m.mu.Lock()
	status.ActiveRuns = len(m.cancels)
	status.MaxConcurrentRuns = m.options.MaxConcurrent
	closed := m.closed
	m.mu.Unlock()
	if closed {
		status.Reason = "PI 任务管理器已关闭"
		return status
	}
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
	return m.CreatePrepared(owner, req, model, nil)
}

func (m *Manager) CreatePrepared(owner string, req CreateRequest, model Model, prepare PrepareFunc) (Run, error) {
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
	if len(m.cancels) >= m.options.MaxConcurrent {
		return Run{}, ErrBusy
	}
	if len(m.runs) >= maxRuns {
		return Run{}, fmt.Errorf("PI 试验记录已达 1000 条，请先由管理员离线归档独立数据目录")
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	run := &storedRun{OwnerID: owner, Run: Run{ID: id, Mode: req.Mode, Title: req.Title, Prompt: req.Prompt, Scope: req.Scope,
		AIChannel: req.AIChannel, Model: model.ID, Status: "queued", Limits: limits, CreatedAt: now, UpdatedAt: now,
		Agents: []Agent{}, Nodes: []Node{}, Edges: []Edge{}, Findings: []Finding{}, Skills: []string{}, ExecutionIDs: []string{}}}
	var prepared *PreparedRun
	if req.Mode == ModePlatform {
		if prepare == nil {
			return Run{}, ErrPlatformUnavailable
		}
		prepared, err = prepare(context.Background(), id, req)
		if err != nil {
			return Run{}, err
		}
		if prepared == nil || prepared.Platform == nil || prepared.Execute == nil {
			if prepared != nil && prepared.Close != nil {
				prepared.Close()
			}
			return Run{}, ErrPlatformUnavailable
		}
		run.ProjectID, run.ConversationID, run.Role = prepared.Platform.ProjectID, prepared.Platform.ConversationID, prepared.Platform.RoleName
		run.AssistantMessageID = prepared.AssistantMessageID
		if run.ProjectID != req.ProjectID || run.ConversationID == "" || run.Role != req.Role {
			if prepared.Close != nil {
				prepared.Close()
			}
			return Run{}, ErrPlatformUnavailable
		}
	}
	cleanup := func() {
		if prepared != nil && prepared.Close != nil {
			prepared.Close()
		}
	}
	workdir := filepath.Join(m.options.Root, "runs", id, "workspace")
	if err := os.MkdirAll(workdir, 0700); err != nil {
		cleanup()
		return Run{}, ErrStorage
	}
	if err := m.saveLocked(run); err != nil {
		cleanup()
		return Run{}, err
	}
	m.runs[id] = run
	base := context.Background()
	if prepared != nil && prepared.Context != nil {
		base = prepared.Context
	}
	ctx, cancel := context.WithTimeout(base, time.Duration(limits.TimeoutSeconds)*time.Second)
	if prepared != nil && prepared.Start != nil {
		if err := prepared.Start(ctx, cancel); err != nil {
			cancel()
			run.Status = "failed"
			run.Error = "平台任务启动失败"
			m.finishPreparedLocked(run, prepared)
			_ = m.saveLocked(run)
			cleanup()
			return Run{}, err
		}
	}
	m.cancels[id] = cancel
	input := Input{RunID: id, Mode: req.Mode, Prompt: req.Prompt, Scope: append([]string{}, req.Scope...), Limits: limits, Model: model}
	if prepared != nil {
		input.Platform = prepared.Platform
		input.Execute = func(ctx context.Context, call ToolCall) (*ToolReply, error) {
			reply, err := prepared.Execute(ctx, call)
			m.mu.Lock()
			if reply != nil && reply.ExecutionID != "" {
				run.ExecutionIDs = appendUnique(run.ExecutionIDs, reply.ExecutionID, limits.MaxToolCalls)
			}
			if err == nil && reply != nil && !reply.IsError && call.Name == "load_skill" {
				name, _ := call.Arguments["name"].(string)
				if name != "" {
					run.Skills = appendUnique(run.Skills, name, 256)
				}
			}
			storeErr := m.saveLocked(run)
			m.mu.Unlock()
			if err == nil && storeErr != nil {
				return reply, storeErr
			}
			return reply, err
		}
	}
	result := cloneRun(run.Run)
	m.wg.Add(1)
	go m.execute(ctx, cancel, workdir, input, prepared)
	return result, nil
}

func (m *Manager) execute(ctx context.Context, cancel context.CancelFunc, workdir string, input Input, prepared *PreparedRun) {
	defer m.wg.Done()
	defer cancel()
	defer func() { m.mu.Lock(); delete(m.cancels, input.RunID); m.mu.Unlock() }()
	if prepared != nil && prepared.Close != nil {
		defer prepared.Close()
	}
	m.mu.Lock()
	run := m.runs[input.RunID]
	if !active(run.Status) {
		m.finishPreparedLocked(run, prepared)
		_ = m.saveLocked(run)
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
	if !active(run.Status) {
		m.finishPreparedLocked(run, prepared)
		_ = m.saveLocked(run)
		return
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		run.Status, run.Error = "partial", "达到独立试验时限；已保留当前证据，尚未完成全部测试"
	case ctx.Err() != nil:
		run.Status, run.Error = "cancelled", "PI 运行已取消"
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
	m.finishPreparedLocked(run, prepared)
	finishAgents(&run.Run)
	run.UpdatedAt = time.Now().UTC()
	if m.saveLocked(run) != nil {
		run.Status, run.Error = "failed", ErrStorage.Error()
	}
}

// Caller holds m.mu. Platform database/finalizer hooks run outside it so tool
// completion and cancellation cannot deadlock on PI state persistence.
func (m *Manager) finishPreparedLocked(run *storedRun, prepared *PreparedRun) {
	if prepared == nil || prepared.Finish == nil {
		return
	}
	snapshot := cloneRun(run.Run)
	original := snapshot.Status
	if _, running := m.cancels[run.ID]; running && original != "cancelled" && original != "interrupted" {
		run.Status = "running"
	}
	m.mu.Unlock()
	var finishErr error
	func() {
		defer func() {
			if recover() != nil {
				finishErr = fmt.Errorf("平台收尾异常")
			}
		}()
		finishErr = prepared.Finish(&snapshot)
	}()
	m.mu.Lock()
	if finishErr != nil {
		snapshot.Status = "failed"
		snapshot.Error = "平台报告或任务状态保存失败；PI 记录仍保留已接收报告"
	}
	if snapshot.Status != "completed" && snapshot.Status != "partial" && snapshot.Status != "failed" && snapshot.Status != "cancelled" && snapshot.Status != "interrupted" {
		snapshot.Status = "failed"
		snapshot.Error = "平台收尾状态无效"
	}
	if original != "completed" && snapshot.Status == "completed" {
		snapshot.Status = original
	}
	if run.Status == "cancelled" || run.Status == "interrupted" {
		snapshot.Status = run.Status
	}
	run.Status = snapshot.Status
	if snapshot.Error != "" {
		run.Error = snapshot.Error
	}
	run.Report = snapshot.Report
	for _, id := range snapshot.ExecutionIDs {
		run.ExecutionIDs = appendUnique(run.ExecutionIDs, id, PlatformLimitCaps.MaxToolCalls)
	}
	for _, skill := range snapshot.Skills {
		run.Skills = appendUnique(run.Skills, skill, 256)
	}
}

func appendUnique(values []string, value string, limit int) []string {
	if value == "" {
		return values
	}
	for _, v := range values {
		if v == value {
			return values
		}
	}
	if len(values) >= limit {
		return values
	}
	return append(values, value)
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
			summary := run.Run
			summary.Agents = nil
			summary.Nodes = nil
			summary.Edges = nil
			summary.Findings = nil
			summary.ExecutionIDs = nil
			summary.Report = ""
			summary.Prompt = ""
			result = append(result, cloneRun(summary))
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
	if run.Mode == "" {
		run.Mode = ModeProbe
	}
	run.Skills = append([]string{}, run.Skills...)
	run.ExecutionIDs = append([]string{}, run.ExecutionIDs...)
	run.Scope = append([]string{}, run.Scope...)
	run.Agents = append([]Agent{}, run.Agents...)
	run.Nodes = append([]Node{}, run.Nodes...)
	run.Edges = append([]Edge{}, run.Edges...)
	run.Findings = append([]Finding{}, run.Findings...)
	return run
}
