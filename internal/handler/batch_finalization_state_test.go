package handler

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/agentfinalizer"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/multiagent"

	"go.uber.org/zap"
)

func TestBatchFinalizationDeliveryRequiresFinalizable(t *testing.T) {
	for _, tt := range []struct {
		name, status, want string
		finalizable        bool
	}{
		{"coverage incomplete", "in_progress", BatchTaskStatusBlocked, false},
		{"blocked", "blocked", BatchTaskStatusBlocked, false},
		{"unknown", "", BatchTaskStatusBlocked, false},
		{"human input", "awaiting_hitl", BatchTaskStatusBlocked, false},
		{"misleading completed", "completed", BatchTaskStatusBlocked, false},
		{"failed", "failed", BatchTaskStatusFailed, false},
		{"cancelled", "cancelled", BatchTaskStatusCancelled, false},
		{"timeout", "timeout", "timeout", false},
		{"verified", "completed", BatchTaskStatusCompleted, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := finalizationContinuationState{}
			decision := agentfinalizer.Decision{
				Status: tt.status, Finalizable: tt.finalizable, Finalized: tt.finalizable,
				CompletionReason:    agentfinalizer.ReasonCoverageIncomplete,
				MissingChecks:       []string{"required coverage is incomplete"},
				PendingExecutionIDs: []string{"tool-1"}, EvidenceRefs: []string{"trace:existing"},
			}
			result := &multiagent.RunResult{Response: "candidate", LastAgentTraceInput: "existing-input", LastAgentTraceOutput: "existing-output"}
			decision = finalizationStoppedDecision(decision, &state)
			decision = batchSubTaskDeliveryDecision(result, decision)
			if decision.Status != tt.want || result.Status != tt.want {
				t.Fatalf("decision=%+v result=%+v, want status=%s", decision, result, tt.want)
			}
			if result.Finalized != tt.finalizable || result.CompletionReason != decision.CompletionReason || !reflect.DeepEqual(result.MissingChecks, decision.MissingChecks) {
				t.Fatalf("RunResult did not reflect finalization decision: %+v", result)
			}
			if result.Response != "candidate" || result.LastAgentTraceInput != "existing-input" || result.LastAgentTraceOutput != "existing-output" {
				t.Fatal("delivery-state synchronization overwrote resumable trace/candidate")
			}
			decision.MissingChecks[0] = "mutated"
			if result.MissingChecks[0] == "mutated" {
				t.Fatal("RunResult aliases decision slices")
			}
		})
	}
}

func TestBatchFinalizationStoppedReasonPreserved(t *testing.T) {
	state := finalizationContinuationState{Attempts: 3, StopReason: "自动续跑已停止，保留轨迹供人工恢复"}
	decision := finalizationStoppedDecision(agentfinalizer.Decision{
		Status:           agentfinalizer.StatusInProgress,
		CompletionReason: agentfinalizer.ReasonCoverageIncomplete,
		MissingChecks:    []string{"required check missing"},
	}, &state)
	result := &multiagent.RunResult{}
	decision = batchSubTaskDeliveryDecision(result, decision)
	reason := finalizationBlockedMessage(decision)
	if result.Status != BatchTaskStatusBlocked || !strings.Contains(reason, "coverage_incomplete") || !strings.Contains(reason, state.StopReason) {
		t.Fatalf("blocked delivery lost finalization cause or stop reason: result=%+v reason=%s", result, reason)
	}
}

func TestBatchFinalizationDoneAndHistoryCarryActualStatus(t *testing.T) {
	for _, status := range []string{BatchTaskStatusCompleted, BatchTaskStatusBlocked, BatchTaskStatusFailed, BatchTaskStatusCancelled, "timeout"} {
		t.Run(status, func(t *testing.T) {
			bus := NewTaskEventBus()
			manager := &AgentTaskManager{tasks: make(map[string]*AgentTask), maxHistorySize: 50, historyRetention: 24 * time.Hour}
			manager.SetTaskEventBus(bus)
			_, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if _, err := manager.StartTask("conversation-existing", "test", cancel); err != nil {
				t.Fatal(err)
			}
			_, stream := bus.Subscribe("conversation-existing")
			h := &AgentHandler{tasks: manager, taskEventBus: bus}
			decision := agentfinalizer.Decision{
				Status: status, Finalizable: status == BatchTaskStatusCompleted, Finalized: status == BatchTaskStatusCompleted,
				CompletionReason: agentfinalizer.ReasonCoverageIncomplete,
				MissingChecks:    []string{"coverage still missing"}, PendingExecutionIDs: []string{"tool-existing"},
			}
			// A later runtime failure/cancellation must override a stale successful decision.
			if status == BatchTaskStatusFailed || status == BatchTaskStatusCancelled || status == "timeout" {
				decision.Status, decision.Finalizable, decision.Finalized = BatchTaskStatusCompleted, true, true
			}
			h.finishBatchSubTask("conversation-existing", status, decision)
			line, ok := <-stream
			if !ok {
				t.Fatal("FinishTask closed the stream before publishing done")
			}
			var event struct {
				Type string `json:"type"`
				Data struct {
					Status           string   `json:"status"`
					ConversationID   string   `json:"conversationId"`
					CompletionReason string   `json:"completionReason"`
					Finalizable      bool     `json:"finalizable"`
					Finalized        bool     `json:"finalized"`
					MissingChecks    []string `json:"missingChecks"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(string(line), "data: "))), &event); err != nil {
				t.Fatal(err)
			}
			if event.Type != "done" || event.Data.Status != status || event.Data.ConversationID != "conversation-existing" {
				t.Fatalf("incorrect done event: %s", line)
			}
			if event.Data.Finalizable != (status == BatchTaskStatusCompleted) || event.Data.Finalized != (status == BatchTaskStatusCompleted) {
				t.Fatalf("incorrect delivery flags: %s", line)
			}
			if status == BatchTaskStatusBlocked && (event.Data.CompletionReason != agentfinalizer.ReasonCoverageIncomplete || len(event.Data.MissingChecks) == 0) {
				t.Fatalf("done lost blocking reason: %s", line)
			}
			if _, ok := <-stream; ok {
				t.Fatal("event stream should close after done")
			}
			history := manager.GetCompletedTasks()
			if len(history) != 1 || history[0].Status != status || manager.GetTask("conversation-existing") != nil {
				t.Fatalf("FinishTask recorded incorrect final status: %+v", history)
			}
		})
	}
}

func TestBatchFinalizationQueueStopsPausedWithBlockedTasks(t *testing.T) {
	for _, tt := range []struct{ name, taskStatus, queueStatus, want string }{
		{"blocked", BatchTaskStatusBlocked, BatchQueueStatusRunning, BatchQueueStatusPaused},
		{"completed", BatchTaskStatusCompleted, BatchQueueStatusRunning, BatchQueueStatusCompleted},
		{"failed", BatchTaskStatusFailed, BatchQueueStatusRunning, BatchQueueStatusCompleted},
		{"cancelled", BatchTaskStatusCancelled, BatchQueueStatusRunning, BatchQueueStatusCompleted},
		{"pending sibling", BatchTaskStatusPending, BatchQueueStatusRunning, BatchQueueStatusRunning},
		{"running sibling", BatchTaskStatusRunning, BatchQueueStatusRunning, BatchQueueStatusRunning},
		{"paused queue", BatchTaskStatusBlocked, BatchQueueStatusPaused, BatchQueueStatusPaused},
		{"cancelled queue", BatchTaskStatusBlocked, BatchQueueStatusCancelled, BatchQueueStatusCancelled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewBatchTaskManager(nil)
			queue := batchManagerTestQueue(t, manager)
			manager.UpdateTaskStatus(queue.ID, queue.Tasks[0].ID, BatchTaskStatusCompleted, "verified", "")
			manager.UpdateTaskStatusWithConversationID(queue.ID, queue.Tasks[1].ID, tt.taskStatus, "existing result", "coverage_incomplete: required check missing", "conversation-existing")
			manager.UpdateQueueStatus(queue.ID, tt.queueStatus)
			h := &AgentHandler{batchTaskManager: manager, logger: zap.NewNop()}
			h.tryFinalizeBatchQueue(queue.ID)
			got, _ := manager.GetBatchQueue(queue.ID)
			if got.Status != tt.want {
				t.Fatalf("queue status=%s want=%s", got.Status, tt.want)
			}
			if tt.taskStatus == BatchTaskStatusBlocked && tt.queueStatus == BatchQueueStatusRunning {
				if got.CompletedAt != nil || got.Tasks[1].CompletedAt != nil || !strings.Contains(got.LastRunError, "coverage_incomplete") || got.Tasks[1].ConversationID != "conversation-existing" {
					t.Fatalf("blocked queue lost recovery state: %+v", got)
				}
			}
		})
	}
}

func TestBatchFinalizationBlockedDoesNotPreventSiblingWorkOrAutoRetry(t *testing.T) {
	manager := NewBatchTaskManager(nil)
	queue := batchManagerTestQueue(t, manager)
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	first, ok := manager.ClaimNextPendingTask(queue.ID)
	if !ok {
		t.Fatal("missing first task")
	}
	manager.UpdateTaskStatusWithConversationID(queue.ID, first.ID, BatchTaskStatusBlocked, "blocked result", "coverage_incomplete", "conversation-existing")
	if batchQueueExecutionShouldStop(&BatchTaskQueue{Status: BatchQueueStatusRunning}, true) {
		t.Fatal("blocked subtask must not stop the running queue")
	}
	second, ok := manager.ClaimNextPendingTask(queue.ID)
	if !ok || second.ID == first.ID {
		t.Fatal("blocked subtask prevented sibling claim or was automatically claimed")
	}
	manager.UpdateTaskStatus(queue.ID, second.ID, BatchTaskStatusCompleted, "verified", "")
	h := &AgentHandler{batchTaskManager: manager, logger: zap.NewNop()}
	h.tryFinalizeBatchQueue(queue.ID)
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	if _, ok := manager.ClaimNextPendingTask(queue.ID); ok {
		t.Fatal("resuming queue automatically retried blocked task")
	}
	h.tryFinalizeBatchQueue(queue.ID)
	before, _ := manager.GetBatchQueue(queue.ID)
	if manager.ResetQueueForRerun(queue.ID) {
		t.Fatal("whole-queue reset must not automatically reset blocked tasks")
	}
	after, _ := manager.GetBatchQueue(queue.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected reset mutated recovery state")
	}
	if err := manager.PrepareSingleTaskRun(queue.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	manager.SetSingleRunTask(queue.ID, first.ID)
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	rerun, ok := manager.ClaimNextPendingTask(queue.ID)
	if !ok || rerun.ID != first.ID {
		t.Fatal("explicit single-task rerun could not recover blocked item")
	}
	got, _ := manager.GetBatchQueue(queue.ID)
	if got.Tasks[1].Status != BatchTaskStatusCompleted {
		t.Fatal("single-task rerun reset sibling success")
	}
}

func TestBatchFinalizationBlockedDBFailurePreservesMemory(t *testing.T) {
	manager := NewBatchTaskManager(nil)
	queue := batchManagerTestQueue(t, manager)
	before, _ := manager.GetBatchQueue(queue.ID)
	manager.SetDB(batchManagerTestDB(t, &batchManagerTestConnector{exec: func(string, []driver.NamedValue) error {
		return errors.New("injected blocked-state persistence failure")
	}}))
	manager.UpdateTaskStatusWithConversationID(queue.ID, queue.Tasks[0].ID, BatchTaskStatusBlocked, "candidate", "coverage_incomplete", "conversation-existing")
	after, _ := manager.GetBatchQueue(queue.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed blocked-state write changed cached queue")
	}
}

func TestBatchFinalizationBlockedSQLitePersistence(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "batch-finalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skip("SQLite integration requires CGO")
		}
		t.Fatal(err)
	}
	db := &database.DB{DB: sqlDB}
	for _, stmt := range []string{
		"CREATE TABLE batch_task_queues (id TEXT PRIMARY KEY, title TEXT, role TEXT, agent_mode TEXT, schedule_mode TEXT, cron_expr TEXT, next_run_at DATETIME, schedule_enabled INTEGER, last_schedule_trigger_at DATETIME, last_schedule_error TEXT, last_run_error TEXT, project_id TEXT, independent_projects INTEGER DEFAULT 0, concurrency INTEGER, model_retry_max INTEGER, status TEXT, created_at DATETIME, started_at DATETIME, completed_at DATETIME, current_index INTEGER, owner_user_id TEXT)",
		"CREATE TABLE batch_tasks (id TEXT PRIMARY KEY, queue_id TEXT, message TEXT, conversation_id TEXT, status TEXT, started_at DATETIME, completed_at DATETIME, error TEXT, result TEXT, ai_channel_id TEXT, retry_count INTEGER, project_id TEXT)",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	manager := NewBatchTaskManager(nil)
	manager.SetDB(db)
	queue, err := manager.CreateBatchQueue("test", "", "eino_single", "manual", "", "", nil, 1, 0, batchTaskInputs("test"))
	if err != nil {
		t.Fatal(err)
	}
	taskID := queue.Tasks[0].ID
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	// A stale completed timestamp must be cleared when delivery becomes blocked.
	manager.UpdateTaskStatusWithConversationID(queue.ID, taskID, BatchTaskStatusCompleted, "candidate", "", "conversation-existing")
	manager.UpdateTaskStatus(queue.ID, taskID, BatchTaskStatusBlocked, "", "coverage_incomplete: required check missing")
	h := &AgentHandler{batchTaskManager: manager, logger: zap.NewNop()}
	h.tryFinalizeBatchQueue(queue.ID)
	cold := NewBatchTaskManager(nil)
	cold.SetDB(db)
	loaded, ok := cold.GetBatchQueue(queue.ID)
	if !ok || loaded.Status != BatchQueueStatusPaused || len(loaded.Tasks) != 1 {
		t.Fatalf("incorrect persisted queue: %+v", loaded)
	}
	got := loaded.Tasks[0]
	if got.Status != BatchTaskStatusBlocked || got.CompletedAt != nil || got.ConversationID != "conversation-existing" || got.Result != "candidate" || !strings.Contains(got.Error, "coverage_incomplete") {
		t.Fatalf("cold load lost blocked recovery state: %+v", got)
	}
	if cold.ResetQueueForRerun(queue.ID) {
		t.Fatal("cold-loaded blocked task was automatically reset")
	}
	if err := cold.PrepareSingleTaskRun(queue.ID, taskID); err != nil {
		t.Fatal(err)
	}
	var persistedStatus string
	if err := db.QueryRow("SELECT status FROM batch_tasks WHERE id = ?", taskID).Scan(&persistedStatus); err != nil {
		t.Fatal(err)
	}
	if persistedStatus != BatchTaskStatusPending {
		t.Fatalf("explicit rerun did not persist pending: %s", persistedStatus)
	}
}

// Execute the actual frontend functions locally; no browser or network is needed.
func TestBatchFinalizationFrontendState(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("frontend state test requires Node.js")
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "web", "static", "js", "tasks.js"))
	if err != nil {
		t.Fatal(err)
	}
	prelude := `const assert = require('node:assert/strict');
const elements = new Map();
global.window = {};
global.localStorage = {setItem() {}, getItem() {return null;}};
global.document = {addEventListener() {}, getElementById(id) {return elements.get(id) || null;}, createElement() {return {set textContent(v) {this.innerHTML = String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');}};}};
`
	checks := `
const blocked = {conversationId: 'blocked-conv', status: 'blocked', error: 'coverage_incomplete <unsafe>', startedAt: new Date().toISOString()};
tasksState.allTasks = [{conversationId: 'disappeared', status: 'running'}, blocked];
updateCompletedTasksHistory([]);
assert.equal(tasksState.completedTasksHistory.find(t => t.conversationId === 'disappeared').status, 'unknown');
assert.equal(tasksState.completedTasksHistory.find(t => t.conversationId === 'blocked-conv').status, 'blocked');
assert.equal(tasksState.completedTasksHistory.find(t => t.conversationId === 'blocked-conv').error, blocked.error);
const stats = batchQueueTaskStats({tasks: [blocked, {status: 'completed'}, {status: 'failed'}, {status: 'cancelled'}, {status: 'pending'}]});
assert.equal(stats.completed, 1);
assert.equal(stats.blocked, 1);
assert.equal(stats.completed + stats.failed + stats.cancelled, 3);
assert.equal(batchQueueCanRunSingleTask({status: 'paused'}, blocked), true);
assert.equal(batchQueueCanRunSingleTask({status: 'running'}, blocked), false);
const rendered = renderTaskItem(blocked, {blocked: {text: 'Blocked', class: 'task-status-blocked'}}, true);
assert.ok(rendered.includes('task-status-blocked'));
assert.ok(rendered.includes('coverage_incomplete &lt;unsafe&gt;'));
assert.ok(!rendered.includes('cancelTask('));
elements.set('stat-completed', {textContent: ''});
updateTaskStats([blocked, {status: 'unknown'}, {status: 'completed'}]);
assert.equal(elements.get('stat-completed').textContent, 1);
console.log('batch frontend state checks passed');
`
	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(prelude + string(source) + checks)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("frontend state checks failed: %v\n%s", err, out)
	}
}
