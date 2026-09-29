package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

var (
	// ErrBatchQueueNotFound 队列不存在或已从内存卸载。
	ErrBatchQueueNotFound = errors.New("batch queue not found")
	// ErrBatchQueueExecutorActive executeBatchQueue 协程仍在收尾，禁止删除。
	ErrBatchQueueExecutorActive = errors.New("batch queue executor is still active")
	// ErrBatchQueueStillRunning 队列状态仍为 running（无活跃执行器时的兜底保护）。
	ErrBatchQueueStillRunning = errors.New("batch queue is still running")
)

// 批量任务状态常量
const (
	BatchQueueStatusPending   = "pending"
	BatchQueueStatusRunning   = "running"
	BatchQueueStatusPaused    = "paused"
	BatchQueueStatusCompleted = "completed"
	BatchQueueStatusCancelled = "cancelled"

	BatchTaskStatusPending   = "pending"
	BatchTaskStatusRunning   = "running"
	BatchTaskStatusCompleted = "completed"
	BatchTaskStatusFailed    = "failed"
	BatchTaskStatusCancelled = "cancelled"

	// MaxBatchTasksPerQueue 单个队列最大任务数
	MaxBatchTasksPerQueue = 10000

	// MaxBatchQueueTitleLen 队列标题最大长度
	MaxBatchQueueTitleLen = 200

	// MaxBatchQueueRoleLen 角色名最大长度
	MaxBatchQueueRoleLen = 100

	// DefaultBatchQueueConcurrency 未指定并发且只有一条任务时串行。
	DefaultBatchQueueConcurrency = 1

	// MaxBatchQueueConcurrency 单队列同时执行的子任务上限。高配机器可并行多个目标。
	MaxBatchQueueConcurrency = 32

	// DefaultModelErrorRetryMax 模型报错导致任务中断后的默认自动重试次数。
	DefaultModelErrorRetryMax = 3

	// MaxModelErrorRetryMax 单条任务模型报错自动重试上限。
	MaxModelErrorRetryMax = 8
)

// BatchTask 批量任务项
type BatchTask struct {
	ID             string     `json:"id"`
	Message        string     `json:"message"`
	ConversationID string     `json:"conversationId,omitempty"`
	Status         string     `json:"status"` // pending, running, completed, failed, cancelled
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	CompletedAt    *time.Time `json:"completedAt,omitempty"`
	Error          string     `json:"error,omitempty"`
	Result         string     `json:"result,omitempty"`
	AIChannelID    string     `json:"aiChannelId,omitempty"`
	RetryCount     int        `json:"retryCount,omitempty"`
}

// BatchTaskInput 创建队列时的一条子任务。Message 必填，AIChannelID 空则跟随系统默认模型通道。
type BatchTaskInput struct {
	Message     string `json:"message"`
	AIChannelID string `json:"aiChannelId,omitempty"`
}

// BatchTaskQueue 批量任务队列
type BatchTaskQueue struct {
	ID                    string       `json:"id"`
	Title                 string       `json:"title,omitempty"`
	Role                  string       `json:"role,omitempty"` // 角色名称（空字符串表示默认角色）
	AgentMode             string       `json:"agentMode"`      // single | eino_single | deep | plan_execute | supervisor
	ScheduleMode          string       `json:"scheduleMode"`   // manual | cron
	CronExpr              string       `json:"cronExpr,omitempty"`
	NextRunAt             *time.Time   `json:"nextRunAt,omitempty"`
	ScheduleEnabled       bool         `json:"scheduleEnabled"`
	LastScheduleTriggerAt *time.Time   `json:"lastScheduleTriggerAt,omitempty"`
	LastScheduleError     string       `json:"lastScheduleError,omitempty"`
	LastRunError          string       `json:"lastRunError,omitempty"`
	ProjectID             string       `json:"projectId,omitempty"`
	Concurrency           int          `json:"concurrency"`   // 同时执行的子任务数，默认 1
	ModelRetryMax         int          `json:"modelRetryMax"` // 模型报错中断后的自动重试次数，0 表示不额外重试
	Tasks                 []*BatchTask `json:"tasks"`
	Status                string       `json:"status"` // pending, running, paused, completed, cancelled
	CreatedAt             time.Time    `json:"createdAt"`
	StartedAt             *time.Time   `json:"startedAt,omitempty"`
	CompletedAt           *time.Time   `json:"completedAt,omitempty"`
	CurrentIndex          int          `json:"currentIndex"`
}

// BatchTaskManager 批量任务管理器
type BatchTaskManager struct {
	db             *database.DB
	logger         *zap.Logger
	queues         map[string]*BatchTaskQueue
	taskCancels    map[string]map[string]context.CancelFunc // queueID -> taskID -> 取消函数
	singleRunTasks map[string]string                        // queueID -> taskID，单条执行完成后暂停队列
	queueExecutors map[string]struct{}                      // executeBatchQueue 协程活跃标记（与队列 status 解耦）
	mu             sync.RWMutex                             // 仅保护映射；禁止持有时等待队列锁、访问 DB 或执行回调
	queueOps       map[string]*batchQueueOperation
}

// 队列操作覆盖“校验 -> DB -> 内存提交”，不同队列互不串行。
// 引用数含等待者，最后一个调用退出后回收，避免不存在的 ID 无限积累锁。
type batchQueueOperation struct {
	mu   sync.Mutex
	refs int
}

func (m *BatchTaskManager) lockQueue(queueID string) func() {
	m.mu.Lock()
	if m.queueOps == nil {
		m.queueOps = make(map[string]*batchQueueOperation)
	}
	op := m.queueOps[queueID]
	if op == nil {
		op = &batchQueueOperation{}
		m.queueOps[queueID] = op
	}
	op.refs++
	m.mu.Unlock()
	op.mu.Lock()
	return func() {
		op.mu.Unlock()
		m.mu.Lock()
		op.refs--
		if op.refs == 0 {
			delete(m.queueOps, queueID)
		}
		m.mu.Unlock()
	}
}

// loadedQueue 的返回值仅允许在持有对应队列操作锁时访问，不得对外返回。
func (m *BatchTaskManager) loadedQueue(queueID string) (*BatchTaskQueue, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	queue, ok := m.queues[queueID]
	return queue, ok
}

func cloneBatchTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneBatchTask(task *BatchTask) *BatchTask {
	if task == nil {
		return nil
	}
	out := *task
	out.StartedAt = cloneBatchTime(task.StartedAt)
	out.CompletedAt = cloneBatchTime(task.CompletedAt)
	return &out
}

func cloneBatchQueue(queue *BatchTaskQueue) *BatchTaskQueue {
	if queue == nil {
		return nil
	}
	out := *queue
	out.NextRunAt = cloneBatchTime(queue.NextRunAt)
	out.LastScheduleTriggerAt = cloneBatchTime(queue.LastScheduleTriggerAt)
	out.StartedAt = cloneBatchTime(queue.StartedAt)
	out.CompletedAt = cloneBatchTime(queue.CompletedAt)
	if queue.Tasks != nil {
		out.Tasks = make([]*BatchTask, len(queue.Tasks))
		for i, task := range queue.Tasks {
			out.Tasks[i] = cloneBatchTask(task)
		}
	}
	return &out
}

func (m *BatchTaskManager) loadedQueueIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.queues))
	for id := range m.queues {
		ids = append(ids, id)
	}
	return ids
}

// NewBatchTaskManager 创建批量任务管理器
func NewBatchTaskManager(logger *zap.Logger) *BatchTaskManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &BatchTaskManager{
		logger:         logger,
		queues:         make(map[string]*BatchTaskQueue),
		taskCancels:    make(map[string]map[string]context.CancelFunc),
		singleRunTasks: make(map[string]string),
		queueExecutors: make(map[string]struct{}),
	}
}

// batchQueueExecutionShouldStop 判断 executeBatchQueue 主循环是否应退出。
func batchQueueExecutionShouldStop(queue *BatchTaskQueue, exists bool) bool {
	if !exists || queue == nil {
		return true
	}
	switch queue.Status {
	case BatchQueueStatusCancelled, BatchQueueStatusCompleted, BatchQueueStatusPaused:
		return true
	default:
		return false
	}
}

// TryMarkQueueExecutor 标记队列执行协程已启动；若已有执行协程则返回 false。
func (m *BatchTaskManager) TryMarkQueueExecutor(queueID string) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.queueExecutors[queueID]; exists {
		return false
	}
	m.queueExecutors[queueID] = struct{}{}
	return true
}

// UnmarkQueueExecutor 清除队列执行协程标记（executeBatchQueue defer 调用）。
func (m *BatchTaskManager) UnmarkQueueExecutor(queueID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.queueExecutors, queueID)
}

// ForceUnmarkQueueExecutor 强制清除执行协程标记（暂停态单条重跑等场景回收陈旧槽位）。
func (m *BatchTaskManager) ForceUnmarkQueueExecutor(queueID string) {
	m.UnmarkQueueExecutor(queueID)
}

// IsQueueExecutorActive 队列 executeBatchQueue 协程是否仍在运行。
func (m *BatchTaskManager) IsQueueExecutorActive(queueID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.queueExecutors[queueID]
	return ok
}

// SetDB 设置数据库连接。仅在启动阶段、并发使用管理器之前调用；不支持运行时热切换。
func (m *BatchTaskManager) SetDB(db *database.DB) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
}

// normalizeBatchQueueConcurrency 规范化队列并发数。
func normalizeBatchQueueConcurrency(n int) int {
	if n < 1 {
		return DefaultBatchQueueConcurrency
	}
	if n > MaxBatchQueueConcurrency {
		return MaxBatchQueueConcurrency
	}
	return n
}

// resolveBatchQueueConcurrency 多条独立任务未指定并发时，按任务数并行，而不是退回串行。
func resolveBatchQueueConcurrency(requested, taskCount int) int {
	if requested < 1 {
		if taskCount > 1 {
			requested = taskCount
		} else {
			requested = DefaultBatchQueueConcurrency
		}
	}
	return normalizeBatchQueueConcurrency(requested)
}

// normalizeModelErrorRetryMax 规范化模型报错自动重试次数。负数视为 0。
func normalizeModelErrorRetryMax(n int) int {
	if n < 0 {
		return 0
	}
	if n > MaxModelErrorRetryMax {
		return MaxModelErrorRetryMax
	}
	return n
}

// resolveModelErrorRetryMax 未显式指定时使用默认重试次数。
func resolveModelErrorRetryMax(requested *int) int {
	if requested == nil {
		return DefaultModelErrorRetryMax
	}
	return normalizeModelErrorRetryMax(*requested)
}

// CreateBatchQueue 创建批量任务队列
func (m *BatchTaskManager) CreateBatchQueue(
	title, role, agentMode, scheduleMode, cronExpr, projectID string,
	nextRunAt *time.Time,
	concurrency int,
	modelRetryMax int,
	tasks []BatchTaskInput,
) (*BatchTaskQueue, error) {
	// 输入校验
	if utf8.RuneCountInString(title) > MaxBatchQueueTitleLen {
		return nil, fmt.Errorf("标题不能超过 %d 个字符", MaxBatchQueueTitleLen)
	}
	if utf8.RuneCountInString(role) > MaxBatchQueueRoleLen {
		return nil, fmt.Errorf("角色名不能超过 %d 个字符", MaxBatchQueueRoleLen)
	}
	if len(tasks) > MaxBatchTasksPerQueue {
		return nil, fmt.Errorf("单个队列最多 %d 条任务", MaxBatchTasksPerQueue)
	}

	queueID := time.Now().Format("20060102150405") + "-" + generateShortID()
	unlock := m.lockQueue(queueID)
	defer unlock()
	queue := &BatchTaskQueue{
		ID:              queueID,
		Title:           title,
		Role:            role,
		ProjectID:       strings.TrimSpace(projectID),
		AgentMode:       config.NormalizeAgentMode(agentMode),
		ScheduleMode:    normalizeBatchQueueScheduleMode(scheduleMode),
		CronExpr:        strings.TrimSpace(cronExpr),
		NextRunAt:       cloneBatchTime(nextRunAt),
		ScheduleEnabled: true,
		Concurrency:     resolveBatchQueueConcurrency(concurrency, len(tasks)),
		ModelRetryMax:   normalizeModelErrorRetryMax(modelRetryMax),
		Tasks:           make([]*BatchTask, 0, len(tasks)),
		Status:          BatchQueueStatusPending,
		CreatedAt:       time.Now(),
		CurrentIndex:    0,
	}
	if queue.ScheduleMode != "cron" {
		queue.CronExpr = ""
		queue.NextRunAt = nil
	}

	// 准备数据库保存的任务数据
	dbTasks := make([]map[string]interface{}, 0, len(tasks))

	for _, input := range tasks {
		message := strings.TrimSpace(input.Message)
		if message == "" {
			continue
		}
		taskID := generateShortID()
		task := &BatchTask{
			ID:          taskID,
			Message:     message,
			Status:      BatchTaskStatusPending,
			AIChannelID: strings.TrimSpace(input.AIChannelID),
		}
		queue.Tasks = append(queue.Tasks, task)
		dbTasks = append(dbTasks, map[string]interface{}{
			"id":          taskID,
			"message":     message,
			"aiChannelId": task.AIChannelID,
		})
	}

	// 保存到数据库
	if m.db != nil {
		if err := m.db.CreateBatchQueue(
			queueID,
			title,
			role,
			queue.AgentMode,
			queue.ScheduleMode,
			queue.CronExpr,
			queue.NextRunAt,
			queue.ProjectID,
			queue.Concurrency,
			queue.ModelRetryMax,
			dbTasks,
		); err != nil {
			m.logger.Warn("batch queue DB create failed", zap.String("queueId", queueID), zap.Error(err))
			return nil, fmt.Errorf("创建队列失败: %w", err)
		}
	}

	m.mu.Lock()
	m.queues[queueID] = queue
	m.mu.Unlock()
	return cloneBatchQueue(queue), nil
}

// GetBatchQueue 获取批量任务队列
func (m *BatchTaskManager) GetBatchQueue(queueID string) (*BatchTaskQueue, bool) {
	unlock := m.lockQueue(queueID)
	defer unlock()
	queue, exists := m.loadedQueue(queueID)
	if !exists {
		// 与同队列删除/更新共用操作锁，避免冷加载把已删除的旧行放回缓存。
		queue = m.loadQueueFromDB(queueID)
		if queue == nil {
			return nil, false
		}
		m.mu.Lock()
		m.queues[queueID] = queue
		m.mu.Unlock()
	}
	return cloneBatchQueue(queue), true
}

// loadQueueFromDB 从数据库加载单个队列
func (m *BatchTaskManager) loadQueueFromDB(queueID string) *BatchTaskQueue {
	if m.db == nil {
		return nil
	}

	queueRow, err := m.db.GetBatchQueue(queueID)
	if err != nil || queueRow == nil {
		return nil
	}

	taskRows, err := m.db.GetBatchTasks(queueID)
	if err != nil {
		return nil
	}

	queue := &BatchTaskQueue{
		ID:           queueRow.ID,
		AgentMode:    "eino_single",
		ScheduleMode: "manual",
		Status:       queueRow.Status,
		CreatedAt:    queueRow.CreatedAt,
		CurrentIndex: queueRow.CurrentIndex,
		Tasks:        make([]*BatchTask, 0, len(taskRows)),
	}

	if queueRow.Title.Valid {
		queue.Title = queueRow.Title.String
	}
	if queueRow.Role.Valid {
		queue.Role = queueRow.Role.String
	}
	if queueRow.AgentMode.Valid {
		queue.AgentMode = config.NormalizeAgentMode(queueRow.AgentMode.String)
	}
	if queueRow.ScheduleMode.Valid {
		queue.ScheduleMode = normalizeBatchQueueScheduleMode(queueRow.ScheduleMode.String)
	}
	if queueRow.CronExpr.Valid && queue.ScheduleMode == "cron" {
		queue.CronExpr = strings.TrimSpace(queueRow.CronExpr.String)
	}
	if queueRow.NextRunAt.Valid && queue.ScheduleMode == "cron" {
		t := queueRow.NextRunAt.Time
		queue.NextRunAt = &t
	}
	queue.ScheduleEnabled = true
	if queueRow.ScheduleEnabled.Valid && queueRow.ScheduleEnabled.Int64 == 0 {
		queue.ScheduleEnabled = false
	}
	if queueRow.LastScheduleTriggerAt.Valid {
		t := queueRow.LastScheduleTriggerAt.Time
		queue.LastScheduleTriggerAt = &t
	}
	if queueRow.LastScheduleError.Valid {
		queue.LastScheduleError = strings.TrimSpace(queueRow.LastScheduleError.String)
	}
	if queueRow.LastRunError.Valid {
		queue.LastRunError = strings.TrimSpace(queueRow.LastRunError.String)
	}
	if queueRow.ProjectID.Valid {
		queue.ProjectID = strings.TrimSpace(queueRow.ProjectID.String)
	}
	queue.Concurrency = batchQueueConcurrencyFromRow(queueRow)
	queue.ModelRetryMax = batchQueueModelRetryFromRow(queueRow)
	if queueRow.StartedAt.Valid {
		queue.StartedAt = &queueRow.StartedAt.Time
	}
	if queueRow.CompletedAt.Valid {
		queue.CompletedAt = &queueRow.CompletedAt.Time
	}

	for _, taskRow := range taskRows {
		task := &BatchTask{
			ID:      taskRow.ID,
			Message: taskRow.Message,
			Status:  taskRow.Status,
		}
		if taskRow.ConversationID.Valid {
			task.ConversationID = taskRow.ConversationID.String
		}
		if taskRow.StartedAt.Valid {
			task.StartedAt = &taskRow.StartedAt.Time
		}
		if taskRow.CompletedAt.Valid {
			task.CompletedAt = &taskRow.CompletedAt.Time
		}
		if taskRow.Error.Valid {
			task.Error = taskRow.Error.String
		}
		if taskRow.Result.Valid {
			task.Result = taskRow.Result.String
		}
		if taskRow.AIChannelID.Valid {
			task.AIChannelID = strings.TrimSpace(taskRow.AIChannelID.String)
		}
		if taskRow.RetryCount.Valid {
			task.RetryCount = int(taskRow.RetryCount.Int64)
		}
		queue.Tasks = append(queue.Tasks, task)
	}

	return queue
}

// GetLoadedQueues 获取内存快照，不触发 DB 加载。各队列分别加锁，不保证跨队列同一时刻。
func (m *BatchTaskManager) GetLoadedQueues() []*BatchTaskQueue {
	ids := m.loadedQueueIDs()
	result := make([]*BatchTaskQueue, 0, len(ids))
	for _, id := range ids {
		unlock := m.lockQueue(id)
		if queue, exists := m.loadedQueue(id); exists {
			result = append(result, cloneBatchQueue(queue))
		}
		unlock()
	}
	return result
}

// GetAllQueues 获取所有队列，冷加载不占用全局锁。
func (m *BatchTaskManager) GetAllQueues() []*BatchTaskQueue {
	_ = m.LoadFromDB()
	return m.GetLoadedQueues()
}

// ListQueues 列出队列（支持筛选和分页）
func (m *BatchTaskManager) ListQueues(limit, offset int, status, keyword string) ([]*BatchTaskQueue, int, error) {
	return m.ListQueuesForAccess(limit, offset, status, keyword, "", "")
}

func (m *BatchTaskManager) ListQueuesForAccess(limit, offset int, status, keyword, userID, scope string) ([]*BatchTaskQueue, int, error) {
	var queues []*BatchTaskQueue
	var total int

	// 如果数据库可用，从数据库查询
	if m.db != nil {
		// 获取总数
		count, err := m.db.CountBatchQueuesForAccess(status, keyword, userID, scope)
		if err != nil {
			return nil, 0, fmt.Errorf("统计队列总数失败: %w", err)
		}
		total = count

		// 获取队列列表（只获取ID）
		queueRows, err := m.db.ListBatchQueuesForAccess(limit, offset, status, keyword, userID, scope)
		if err != nil {
			return nil, 0, fmt.Errorf("查询队列列表失败: %w", err)
		}

		// 加载完整的队列信息（从内存或数据库）
		for _, queueRow := range queueRows {
			if queue, exists := m.GetBatchQueue(queueRow.ID); exists {
				queues = append(queues, queue)
			}
		}
	} else {
		// 没有数据库，从独立快照中筛选和分页。
		allQueues := m.GetLoadedQueues()

		// 筛选
		filtered := make([]*BatchTaskQueue, 0)
		for _, queue := range allQueues {
			// 状态筛选
			if status != "" && status != "all" && queue.Status != status {
				continue
			}
			// 关键字搜索（搜索队列ID和标题）
			if keyword != "" {
				keywordLower := strings.ToLower(keyword)
				queueIDLower := strings.ToLower(queue.ID)
				queueTitleLower := strings.ToLower(queue.Title)
				if !strings.Contains(queueIDLower, keywordLower) && !strings.Contains(queueTitleLower, keywordLower) {
					// 也可以搜索创建时间
					createdAtStr := queue.CreatedAt.Format("2006-01-02 15:04:05")
					if !strings.Contains(createdAtStr, keyword) {
						continue
					}
				}
			}
			filtered = append(filtered, queue)
		}

		// 按创建时间倒序排序
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		})

		total = len(filtered)

		// 分页
		start := offset
		if start > len(filtered) {
			start = len(filtered)
		}
		end := start + limit
		if end > len(filtered) {
			end = len(filtered)
		}
		if start < len(filtered) {
			queues = filtered[start:end]
		}
	}

	return queues, total, nil
}

// LoadFromDB 从数据库加载所有队列
func (m *BatchTaskManager) LoadFromDB() error {
	if m.db == nil {
		return nil
	}

	queueRows, err := m.db.GetAllBatchQueues()
	if err != nil {
		return err
	}

	for _, queueRow := range queueRows {
		// 只使用列表行的 ID；在操作锁内重新读取，避免过期列表覆盖新状态。
		m.GetBatchQueue(queueRow.ID)
	}

	return nil
}

// UpdateTaskStatus 更新任务状态
func (m *BatchTaskManager) UpdateTaskStatus(queueID, taskID, status string, result, errorMsg string) {
	m.UpdateTaskStatusWithConversationID(queueID, taskID, status, result, errorMsg, "")
}

// UpdateTaskStatusWithConversationID 更新任务状态（包含conversationId）
func (m *BatchTaskManager) UpdateTaskStatusWithConversationID(queueID, taskID, status string, result, errorMsg, conversationID string) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}

	// DB 优先：先持久化，成功后再更新内存，避免重启后状态不一致
	if m.db != nil {
		if err := m.db.UpdateBatchTaskStatus(queueID, taskID, status, conversationID, result, errorMsg); err != nil {
			m.logger.Warn("batch task DB status update failed, skipping memory update",
				zap.String("queueId", queueID), zap.String("taskId", taskID), zap.Error(err))
			return
		}
	}

	for _, task := range queue.Tasks {
		if task.ID == taskID {
			task.Status = status
			if result != "" {
				task.Result = result
			}
			if status == BatchTaskStatusCompleted {
				task.Error = ""
			} else if errorMsg != "" {
				task.Error = errorMsg
			}
			if conversationID != "" {
				task.ConversationID = conversationID
			}
			now := time.Now()
			if status == BatchTaskStatusRunning && task.StartedAt == nil {
				task.StartedAt = &now
			}
			if status == BatchTaskStatusCompleted || status == BatchTaskStatusFailed || status == BatchTaskStatusCancelled {
				task.CompletedAt = &now
			}
			break
		}
	}
}

// UpdateQueueStatus 更新队列状态
func (m *BatchTaskManager) UpdateQueueStatus(queueID, status string) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}

	// DB 优先：先持久化，成功后再更新内存
	if m.db != nil {
		if err := m.db.UpdateBatchQueueStatus(queueID, status); err != nil {
			m.logger.Warn("batch queue DB status update failed, skipping memory update",
				zap.String("queueId", queueID), zap.Error(err))
			return
		}
	}

	queue.Status = status
	now := time.Now()
	if status == BatchQueueStatusRunning && queue.StartedAt == nil {
		queue.StartedAt = &now
	}
	if status == BatchQueueStatusCompleted || status == BatchQueueStatusCancelled {
		queue.CompletedAt = &now
	}
}

// UpdateQueueSchedule 更新队列调度配置
func (m *BatchTaskManager) UpdateQueueSchedule(queueID, scheduleMode, cronExpr string, nextRunAt *time.Time) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}

	scheduleMode = normalizeBatchQueueScheduleMode(scheduleMode)
	cronExpr = strings.TrimSpace(cronExpr)
	nextRunAt = cloneBatchTime(nextRunAt)
	if scheduleMode != "cron" {
		cronExpr = ""
		nextRunAt = nil
	}
	if m.db != nil {
		if err := m.db.UpdateBatchQueueSchedule(queueID, scheduleMode, cronExpr, nextRunAt); err != nil {
			m.logger.Warn("batch queue DB schedule update failed", zap.String("queueId", queueID), zap.Error(err))
			return
		}
	}
	queue.ScheduleMode, queue.CronExpr, queue.NextRunAt = scheduleMode, cronExpr, nextRunAt
}

// batchQueueConcurrencyFromRow 从数据库行读取并发数（缺省为 1）。
func batchQueueConcurrencyFromRow(row *database.BatchTaskQueueRow) int {
	if row == nil || !row.Concurrency.Valid {
		return DefaultBatchQueueConcurrency
	}
	return normalizeBatchQueueConcurrency(int(row.Concurrency.Int64))
}

func batchQueueModelRetryFromRow(row *database.BatchTaskQueueRow) int {
	if row == nil || !row.ModelRetryMax.Valid {
		return DefaultModelErrorRetryMax
	}
	return normalizeModelErrorRetryMax(int(row.ModelRetryMax.Int64))
}

// UpdateQueueMetadata 更新队列标题、角色、代理模式和并发数（非 running 时可用）
func (m *BatchTaskManager) UpdateQueueMetadata(queueID, title, role, agentMode string, concurrency *int) error {
	if utf8.RuneCountInString(title) > MaxBatchQueueTitleLen {
		return fmt.Errorf("标题不能超过 %d 个字符", MaxBatchQueueTitleLen)
	}
	if utf8.RuneCountInString(role) > MaxBatchQueueRoleLen {
		return fmt.Errorf("角色名不能超过 %d 个字符", MaxBatchQueueRoleLen)
	}
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return fmt.Errorf("队列不存在")
	}
	if queue.Status == BatchQueueStatusRunning {
		return fmt.Errorf("队列正在运行中，无法修改")
	}

	// 如果未传 agentMode，保留原值
	if strings.TrimSpace(agentMode) != "" {
		agentMode = config.NormalizeAgentMode(agentMode)
	} else {
		agentMode = queue.AgentMode
	}

	nextConcurrency := queue.Concurrency
	if concurrency != nil {
		nextConcurrency = normalizeBatchQueueConcurrency(*concurrency)
	}
	if m.db != nil {
		if err := m.db.UpdateBatchQueueMetadata(queueID, title, role, agentMode, nextConcurrency); err != nil {
			return fmt.Errorf("更新队列信息失败: %w", err)
		}
	}
	queue.Title, queue.Role, queue.AgentMode = title, role, agentMode
	queue.Concurrency = nextConcurrency
	return nil
}

// SetScheduleEnabled 暂停/恢复 Cron 自动调度（不影响手工执行）
func (m *BatchTaskManager) SetScheduleEnabled(queueID string, enabled bool) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return false
	}
	if m.db != nil {
		if err := m.db.UpdateBatchQueueScheduleEnabled(queueID, enabled); err != nil {
			m.logger.Warn("batch queue DB schedule enabled update failed", zap.Error(err))
			return false
		}
	}
	queue.ScheduleEnabled = enabled
	return true
}

// RecordScheduledRunStart Cron 触发成功、即将执行子任务时调用
func (m *BatchTaskManager) RecordScheduledRunStart(queueID string) {
	now := time.Now()
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}
	if m.db != nil {
		if err := m.db.RecordBatchQueueScheduledTriggerStart(queueID, now); err != nil {
			m.logger.Warn("batch queue DB scheduled trigger update failed", zap.Error(err))
			return
		}
	}
	queue.LastScheduleTriggerAt = &now
	queue.LastScheduleError = ""
}

// SetLastScheduleError 调度层失败（未成功开始执行）
func (m *BatchTaskManager) SetLastScheduleError(queueID, msg string) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}
	msg = strings.TrimSpace(msg)
	if m.db != nil {
		if err := m.db.SetBatchQueueLastScheduleError(queueID, msg); err != nil {
			m.logger.Warn("batch queue DB schedule error update failed", zap.Error(err))
			return
		}
	}
	queue.LastScheduleError = msg
}

// SetLastRunError 最近一轮批量执行中的失败摘要
func (m *BatchTaskManager) SetLastRunError(queueID, msg string) {
	msg = strings.TrimSpace(msg)
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}
	if m.db != nil {
		if err := m.db.SetBatchQueueLastRunError(queueID, msg); err != nil {
			m.logger.Warn("batch queue DB run error update failed", zap.Error(err))
			return
		}
	}
	queue.LastRunError = msg
}

// ResetQueueForRerun 重置队列与子任务状态，供 cron 下一轮执行
func (m *BatchTaskManager) ResetQueueForRerun(queueID string) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return false
	}

	// DB 优先：先持久化重置，成功后再更新内存，避免 DB 失败导致内存脏状态
	if m.db != nil {
		if err := m.db.ResetBatchQueueForRerun(queueID); err != nil {
			m.logger.Warn("batch queue DB reset for rerun failed, skipping memory update",
				zap.String("queueId", queueID), zap.Error(err))
			return false
		}
	}

	queue.Status = BatchQueueStatusPending
	queue.CurrentIndex = 0
	queue.StartedAt = nil
	queue.CompletedAt = nil
	queue.NextRunAt = nil
	queue.LastRunError = ""
	queue.LastScheduleError = ""
	for _, task := range queue.Tasks {
		task.Status = BatchTaskStatusPending
		task.ConversationID = ""
		task.StartedAt = nil
		task.CompletedAt = nil
		task.Error = ""
		task.Result = ""
		task.RetryCount = 0
	}
	return true
}

// UpdateTaskMessage 更新任务消息（队列空闲时可改；任务需非 running）
func (m *BatchTaskManager) UpdateTaskMessage(queueID, taskID, message string) error {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return fmt.Errorf("队列不存在")
	}

	if !queueAllowsTaskListMutationLocked(queue) {
		return fmt.Errorf("队列正在执行或未就绪，无法编辑任务")
	}

	// 查找并更新任务
	for _, task := range queue.Tasks {
		if task.ID == taskID {
			if task.Status == BatchTaskStatusRunning {
				return fmt.Errorf("执行中的任务不能编辑")
			}
			if m.db != nil {
				if err := m.db.UpdateBatchTaskMessage(queueID, taskID, message); err != nil {
					return fmt.Errorf("更新任务消息失败: %w", err)
				}
			}
			task.Message = message
			return nil
		}
	}

	return fmt.Errorf("任务不存在")
}

// UpdateTaskChannel 更新子任务模型通道。空字符串表示跟随系统默认通道。
func (m *BatchTaskManager) UpdateTaskChannel(queueID, taskID, aiChannelID string) error {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return fmt.Errorf("队列不存在")
	}
	if !queueAllowsTaskListMutationLocked(queue) {
		return fmt.Errorf("队列正在执行或未就绪，无法编辑任务")
	}
	aiChannelID = strings.TrimSpace(aiChannelID)
	for _, task := range queue.Tasks {
		if task.ID != taskID {
			continue
		}
		if task.Status == BatchTaskStatusRunning {
			return fmt.Errorf("执行中的任务不能编辑")
		}
		if m.db != nil {
			if err := m.db.UpdateBatchTaskChannel(queueID, taskID, aiChannelID); err != nil {
				return fmt.Errorf("更新任务模型失败: %w", err)
			}
		}
		task.AIChannelID = aiChannelID
		return nil
	}
	return fmt.Errorf("任务不存在")
}

// NoteTaskModelRetry 记录模型报错后的自动重试，任务保持运行中。
func (m *BatchTaskManager) NoteTaskModelRetry(queueID, taskID string, retryCount int, errText string) {
	unlock := m.lockQueue(queueID)
	defer unlock()
	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}
	note := fmt.Sprintf("模型报错，正在第 %d 次自动重试：%s", retryCount, trimBatchRetryNote(errText))
	if m.db != nil {
		if err := m.db.UpdateBatchTaskRetry(queueID, taskID, retryCount, note); err != nil {
			m.logger.Warn("batch task retry note failed", zap.String("queueId", queueID), zap.String("taskId", taskID), zap.Error(err))
			return
		}
	}
	for _, task := range queue.Tasks {
		if task.ID == taskID {
			task.RetryCount = retryCount
			task.Error = note
			task.Status = BatchTaskStatusRunning
			break
		}
	}
}

func trimBatchRetryNote(s string) string {
	s = strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
	if utf8.RuneCountInString(s) <= 240 {
		return s
	}
	return string([]rune(s)[:240]) + "..."
}

// AddTaskToQueue 添加任务到队列（队列空闲时可添加：含 cron 本轮 completed、手动暂停后等）
func (m *BatchTaskManager) AddTaskToQueue(queueID, message, aiChannelID string) (*BatchTask, error) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return nil, fmt.Errorf("队列不存在")
	}

	if !queueAllowsTaskListMutationLocked(queue) {
		return nil, fmt.Errorf("队列正在执行或未就绪，无法添加任务")
	}

	if message == "" {
		return nil, fmt.Errorf("任务消息不能为空")
	}

	// 生成任务ID
	taskID := generateShortID()
	task := &BatchTask{
		ID:          taskID,
		Message:     message,
		Status:      BatchTaskStatusPending,
		AIChannelID: strings.TrimSpace(aiChannelID),
	}

	// DB 成功后再发布新任务。
	if m.db != nil {
		if err := m.db.AddBatchTask(queueID, taskID, message, task.AIChannelID); err != nil {
			return nil, fmt.Errorf("添加任务失败: %w", err)
		}
	}
	queue.Tasks = append(queue.Tasks, task)
	return cloneBatchTask(task), nil
}

// PrepareSingleTaskRun 准备单条执行：重置目标任务（若已有结果）并定位队列索引
func (m *BatchTaskManager) PrepareSingleTaskRun(queueID, taskID string) error {
	unlock := m.lockQueue(queueID)
	var cancelFuncs []context.CancelFunc
	defer func() {
		unlock()
		for _, cancel := range cancelFuncs {
			cancel()
		}
	}()
	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return fmt.Errorf("队列不存在")
	}
	var task *BatchTask
	taskIndex := -1
	for i, t := range queue.Tasks {
		if t != nil && t.ID == taskID {
			task, taskIndex = t, i
			break
		}
	}
	if task == nil {
		return fmt.Errorf("任务不存在")
	}
	if !queueAllowsSingleTaskRunLocked(queue, task) {
		return fmt.Errorf("队列正在执行或未就绪，无法单条执行")
	}
	var siblings []*BatchTask
	if queue.Status == BatchQueueStatusPaused {
		for _, t := range queue.Tasks {
			if t != nil && t.ID != taskID && t.Status == BatchTaskStatusRunning {
				siblings = append(siblings, t)
			}
		}
	}
	needsReset := task.Status != BatchTaskStatusPending
	resumeQueue := queue.Status == BatchQueueStatusCompleted || queue.Status == BatchQueueStatusCancelled
	now := time.Now()
	const staleRunMsg = "为单条执行其它任务，已中止"
	if m.db != nil {
		// 兄弟任务收口和目标重置在同一事务内，任何失败均不修改内存或取消函数。
		tx, err := m.db.Begin()
		if err != nil {
			return fmt.Errorf("准备单条执行失败: %w", err)
		}
		defer tx.Rollback()
		for _, sibling := range siblings {
			if _, err = tx.Exec("UPDATE batch_tasks SET status = ?, completed_at = ?, error = ? WHERE queue_id = ? AND id = ?",
				BatchTaskStatusCancelled, now, staleRunMsg, queueID, sibling.ID); err != nil {
				return err
			}
		}
		if needsReset {
			if _, err = tx.Exec("UPDATE batch_tasks SET status = ?, conversation_id = NULL, started_at = NULL, completed_at = NULL, error = NULL, result = NULL, retry_count = 0 WHERE queue_id = ? AND id = ?",
				BatchTaskStatusPending, queueID, taskID); err != nil {
				return err
			}
		}
		if resumeQueue {
			_, err = tx.Exec("UPDATE batch_task_queues SET status = ?, current_index = ?, completed_at = NULL, last_run_error = NULL WHERE id = ?",
				BatchQueueStatusPaused, taskIndex, queueID)
		} else {
			_, err = tx.Exec("UPDATE batch_task_queues SET current_index = ?, last_run_error = NULL WHERE id = ?", taskIndex, queueID)
		}
		if err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	for _, sibling := range siblings {
		sibling.Status, sibling.Error = BatchTaskStatusCancelled, staleRunMsg
		sibling.CompletedAt = &now
	}
	if needsReset {
		task.Status = BatchTaskStatusPending
		task.ConversationID = ""
		task.StartedAt = nil
		task.CompletedAt = nil
		task.Error = ""
		task.Result = ""
		task.RetryCount = 0
	}
	queue.CurrentIndex = taskIndex
	queue.LastRunError = ""
	if queue.Status == BatchQueueStatusPaused {
		m.mu.Lock()
		cancelFuncs = m.drainTaskCancelsLocked(queueID)
		m.mu.Unlock()
	}
	if resumeQueue {
		queue.Status = BatchQueueStatusPaused
		queue.CompletedAt = nil
	}
	return nil
}

// SetSingleRunTask 标记队列仅执行指定子任务，完成后自动暂停
func (m *BatchTaskManager) SetSingleRunTask(queueID, taskID string) {
	unlock := m.lockQueue(queueID)
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.singleRunTasks == nil {
		m.singleRunTasks = make(map[string]string)
	}
	m.singleRunTasks[queueID] = taskID
}

// ClearSingleRunTask 清除单条执行标记
func (m *BatchTaskManager) ClearSingleRunTask(queueID string) {
	unlock := m.lockQueue(queueID)
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.singleRunTasks, queueID)
}

// TakeSingleRunTaskIfMatch 若刚完成的子任务为单条执行目标，则清除标记并返回 true
func (m *BatchTaskManager) TakeSingleRunTaskIfMatch(queueID, taskID string) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.singleRunTasks == nil {
		return false
	}
	if m.singleRunTasks[queueID] != taskID {
		return false
	}
	delete(m.singleRunTasks, queueID)
	return true
}

// DeleteTask 删除任务（队列空闲时可删；执行中任务不可删）
func (m *BatchTaskManager) DeleteTask(queueID, taskID string) error {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return fmt.Errorf("队列不存在")
	}

	if !queueAllowsTaskListMutationLocked(queue) {
		return fmt.Errorf("队列正在执行或未就绪，无法删除任务")
	}

	// 查找任务
	taskIndex := -1
	for i, task := range queue.Tasks {
		if task.ID == taskID {
			if task.Status == BatchTaskStatusRunning {
				return fmt.Errorf("执行中的任务不能删除")
			}
			taskIndex = i
			break
		}
	}

	if taskIndex == -1 {
		return fmt.Errorf("任务不存在")
	}

	// DB 优先：先从数据库删除，成功后再从内存移除
	if m.db != nil {
		if err := m.db.DeleteBatchTask(queueID, taskID); err != nil {
			return fmt.Errorf("删除任务失败: %w", err)
		}
	}

	queue.Tasks = append(queue.Tasks[:taskIndex], queue.Tasks[taskIndex+1:]...)
	return nil
}

func queueHasRunningTaskLocked(queue *BatchTaskQueue) bool {
	if queue == nil {
		return false
	}
	for _, t := range queue.Tasks {
		if t != nil && t.Status == BatchTaskStatusRunning {
			return true
		}
	}
	return false
}

// queueAllowsTaskListMutationLocked 是否允许增删改子任务文案/列表（必须在持有对应队列操作锁下调用）
func queueAllowsTaskListMutationLocked(queue *BatchTaskQueue) bool {
	if queue == nil {
		return false
	}
	if queue.Status == BatchQueueStatusRunning {
		return false
	}
	if queueHasRunningTaskLocked(queue) {
		return false
	}
	switch queue.Status {
	case BatchQueueStatusPending, BatchQueueStatusPaused, BatchQueueStatusCompleted, BatchQueueStatusCancelled:
		return true
	default:
		return false
	}
}

// queueAllowsSingleTaskRunLocked 是否允许对指定子任务发起单条执行（必须在持有对应队列操作锁下调用）
func queueAllowsSingleTaskRunLocked(queue *BatchTaskQueue, task *BatchTask) bool {
	if queue == nil || task == nil {
		return false
	}
	if task.Status == BatchTaskStatusRunning {
		return false
	}
	if queue.Status == BatchQueueStatusRunning {
		return false
	}
	switch queue.Status {
	case BatchQueueStatusPending, BatchQueueStatusPaused, BatchQueueStatusCompleted, BatchQueueStatusCancelled:
		return true
	default:
		return false
	}
}

// ClaimNextPendingTask 原子领取下一个待执行子任务（并发 worker 安全）。
func (m *BatchTaskManager) ClaimNextPendingTask(queueID string) (*BatchTask, bool) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists || queue == nil {
		return nil, false
	}
	if queue.Status == BatchQueueStatusCancelled || queue.Status == BatchQueueStatusCompleted || queue.Status == BatchQueueStatusPaused {
		return nil, false
	}

	m.mu.RLock()
	onlyTaskID := m.singleRunTasks[queueID]
	m.mu.RUnlock()

	for i, task := range queue.Tasks {
		if task == nil || task.Status != BatchTaskStatusPending {
			continue
		}
		if onlyTaskID != "" && task.ID != onlyTaskID {
			continue
		}
		task.Status = BatchTaskStatusRunning
		queue.CurrentIndex = i
		return cloneBatchTask(task), true
	}
	return nil, false
}

// HasRunningTasks 队列是否仍有 running 状态的子任务。
func (m *BatchTaskManager) HasRunningTasks(queueID string) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()
	queue, exists := m.loadedQueue(queueID)
	if !exists || queue == nil {
		return false
	}
	for _, task := range queue.Tasks {
		if task != nil && task.Status == BatchTaskStatusRunning {
			return true
		}
	}
	return false
}

// HasPendingOrRunningTasks 队列是否仍有未完成的子任务。
func (m *BatchTaskManager) HasPendingOrRunningTasks(queueID string) bool {
	unlock := m.lockQueue(queueID)
	defer unlock()
	queue, exists := m.loadedQueue(queueID)
	if !exists || queue == nil {
		return false
	}
	for _, task := range queue.Tasks {
		if task == nil {
			continue
		}
		if task.Status == BatchTaskStatusPending || task.Status == BatchTaskStatusRunning {
			return true
		}
	}
	return false
}

// drainTaskCancelsLocked 取出并清空队列下所有子任务取消函数（调用方须已持 m.mu）。
func (m *BatchTaskManager) drainTaskCancelsLocked(queueID string) []context.CancelFunc {
	taskMap, ok := m.taskCancels[queueID]
	if !ok || len(taskMap) == 0 {
		return nil
	}
	cancels := make([]context.CancelFunc, 0, len(taskMap))
	for _, c := range taskMap {
		if c != nil {
			cancels = append(cancels, c)
		}
	}
	delete(m.taskCancels, queueID)
	return cancels
}

// GetNextTask 获取下一个待执行的任务（串行兼容，优先使用 ClaimNextPendingTask）
func (m *BatchTaskManager) GetNextTask(queueID string) (*BatchTask, bool) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return nil, false
	}

	for i := queue.CurrentIndex; i < len(queue.Tasks); i++ {
		task := queue.Tasks[i]
		if task.Status == BatchTaskStatusPending {
			queue.CurrentIndex = i
			return cloneBatchTask(task), true
		}
	}

	return nil, false
}

// MoveToNextTask 移动到下一个任务
func (m *BatchTaskManager) MoveToNextTask(queueID string) {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return
	}

	if m.db != nil {
		if err := m.db.UpdateBatchQueueCurrentIndex(queueID, queue.CurrentIndex+1); err != nil {
			m.logger.Warn("batch queue DB index update failed", zap.String("queueId", queueID), zap.Error(err))
			return
		}
	}
	queue.CurrentIndex++
}

// SetTaskCancel 设置子任务的取消函数
func (m *BatchTaskManager) SetTaskCancel(queueID, taskID string, cancel context.CancelFunc) {
	unlock := m.lockQueue(queueID)
	defer unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel == nil {
		if taskMap, ok := m.taskCancels[queueID]; ok {
			delete(taskMap, taskID)
			if len(taskMap) == 0 {
				delete(m.taskCancels, queueID)
			}
		}
		return
	}
	if m.taskCancels[queueID] == nil {
		m.taskCancels[queueID] = make(map[string]context.CancelFunc)
	}
	m.taskCancels[queueID][taskID] = cancel
}

// PauseQueue 暂停队列
func (m *BatchTaskManager) PauseQueue(queueID string) bool {
	unlock := m.lockQueue(queueID)
	var cancelFuncs []context.CancelFunc
	defer func() {
		unlock()
		for _, cancel := range cancelFuncs {
			cancel()
		}
	}()
	queue, exists := m.loadedQueue(queueID)
	if !exists || queue.Status != BatchQueueStatusRunning {
		return false
	}
	if m.db != nil {
		if err := m.db.UpdateBatchQueueStatus(queueID, BatchQueueStatusPaused); err != nil {
			m.logger.Warn("batch queue DB pause update failed, skipping memory update",
				zap.String("queueId", queueID), zap.Error(err))
			return false
		}
	}
	queue.Status = BatchQueueStatusPaused
	m.mu.Lock()
	cancelFuncs = m.drainTaskCancelsLocked(queueID)
	m.mu.Unlock()
	return true
}

// CancelQueue 取消队列（保留此方法以保持向后兼容，但建议使用PauseQueue）
func (m *BatchTaskManager) CancelQueue(queueID string) bool {
	unlock := m.lockQueue(queueID)
	var cancelFuncs []context.CancelFunc
	defer func() {
		unlock()
		for _, cancel := range cancelFuncs {
			cancel()
		}
	}()
	queue, exists := m.loadedQueue(queueID)
	if !exists || queue.Status == BatchQueueStatusCompleted || queue.Status == BatchQueueStatusCancelled {
		return false
	}
	now := time.Now()
	if m.db != nil {
		if err := m.persistQueueCancellation(queueID, now); err != nil {
			m.logger.Warn("batch queue DB cancel failed, skipping memory update", zap.String("queueId", queueID), zap.Error(err))
			return false
		}
	}
	queue.Status = BatchQueueStatusCancelled
	queue.CompletedAt = &now
	for _, task := range queue.Tasks {
		if task != nil && task.Status == BatchTaskStatusPending {
			task.Status = BatchTaskStatusCancelled
			task.CompletedAt = &now
		}
	}
	m.mu.Lock()
	cancelFuncs = m.drainTaskCancelsLocked(queueID)
	m.mu.Unlock()
	return true
}

// 队列和 pending 子任务必须一起提交，避免第二条 SQL 失败留下半取消状态。
func (m *BatchTaskManager) persistQueueCancellation(queueID string, now time.Time) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE batch_tasks SET status = ?, completed_at = ? WHERE queue_id = ? AND status = ?",
		BatchTaskStatusCancelled, now, queueID, BatchTaskStatusPending); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE batch_task_queues SET status = ?, completed_at = ? WHERE id = ?",
		BatchQueueStatusCancelled, now, queueID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteQueue 删除队列。执行协程活跃或 status 为 running 时拒绝删除，避免 executeBatchQueue 空指针 panic。
func (m *BatchTaskManager) DeleteQueue(queueID string) error {
	unlock := m.lockQueue(queueID)
	defer unlock()

	queue, exists := m.loadedQueue(queueID)
	if !exists {
		return ErrBatchQueueNotFound
	}

	if m.IsQueueExecutorActive(queueID) {
		return ErrBatchQueueExecutorActive
	}

	// 运行中的队列不允许删除，防止孤儿协程和数据丢失
	if queue.Status == BatchQueueStatusRunning {
		return ErrBatchQueueStillRunning
	}

	if m.db != nil {
		if err := m.db.DeleteBatchQueue(queueID); err != nil {
			return fmt.Errorf("删除队列失败: %w", err)
		}
	}
	m.mu.Lock()
	delete(m.taskCancels, queueID)
	delete(m.singleRunTasks, queueID)
	delete(m.queues, queueID)
	m.mu.Unlock()
	return nil
}

// generateShortID 生成短ID
func generateShortID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return time.Now().Format("150405") + "-" + hex.EncodeToString(b)
}
