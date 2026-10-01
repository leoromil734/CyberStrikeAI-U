package handler

import (
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestPauseQueuePreservesInterruptedTasksForContinuation(t *testing.T) {
	manager := NewBatchTaskManager(zap.NewNop())
	queue, err := manager.CreateBatchQueue("pause", "", "eino_single", "manual", "", "", nil, 2, 0, batchTaskInputs("first", "second", "third"))
	if err != nil {
		t.Fatal(err)
	}
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	first, _ := manager.ClaimNextPendingTask(queue.ID)
	second, _ := manager.ClaimNextPendingTask(queue.ID)
	manager.UpdateTaskStatusWithConversationID(queue.ID, first.ID, BatchTaskStatusRunning, "partial evidence", "", "existing-conversation")
	cancelled := 0
	for _, task := range []*BatchTask{first, second} {
		manager.SetTaskCancel(queue.ID, task.ID, func() {
			cancelled++
			if snapshot, _ := manager.GetBatchQueue(queue.ID); snapshot.Status != BatchQueueStatusPaused {
				t.Error("cancel callback ran before pause was committed")
			}
		})
	}
	if !manager.PauseQueue(queue.ID) || cancelled != 2 {
		t.Fatalf("pause did not stop both workers: count=%d", cancelled)
	}
	paused, _ := manager.GetBatchQueue(queue.ID)
	if paused.Tasks[0].Status != BatchTaskStatusPaused || paused.Tasks[1].Status != BatchTaskStatusPaused || paused.Tasks[2].Status != BatchTaskStatusPending || paused.Tasks[0].CompletedAt != nil || paused.Tasks[0].Result != "partial evidence" {
		t.Fatalf("pause masqueraded as cancellation/completion: %+v", paused.Tasks)
	}
	if _, ok := manager.ClaimNextPendingTask(queue.ID); ok {
		t.Fatal("paused queue continued launching work")
	}
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	resumed, ok := manager.ClaimNextPendingTask(queue.ID)
	if !ok || !resumed.ResumeFromPause || resumed.ConversationID != "existing-conversation" || resumed.Result != "partial evidence" {
		t.Fatalf("continuation lost prior context: %+v", resumed)
	}
}

func TestCancelledOnlyPausedQueueCannotCompleteByEmptyResume(t *testing.T) {
	h, owner := newPrivateBatchHandler(t)
	queue, err := h.batchTaskManager.CreateBatchQueue("legacy pause", "", "eino_single", "manual", "", "", nil, 1, 0,
		batchTaskInputs("unit task"), database.BatchQueueCreateOptions{OwnerUserID: owner})
	if err != nil {
		t.Fatal(err)
	}
	h.batchTaskManager.UpdateTaskStatus(queue.ID, queue.Tasks[0].ID, BatchTaskStatusCancelled, "stopped", "")
	h.batchTaskManager.UpdateQueueStatus(queue.ID, BatchQueueStatusPaused)
	found, err := h.startBatchQueueExecution(queue.ID, false)
	if !found || err == nil || !strings.Contains(err.Error(), "没有待执行") {
		t.Fatalf("empty resume incorrectly started/completed a queue: found=%v err=%v", found, err)
	}
	current, _ := h.batchTaskManager.GetBatchQueue(queue.ID)
	if current.Status != BatchQueueStatusPaused || h.batchTaskManager.IsQueueExecutorActive(queue.ID) {
		t.Fatal("empty resume changed state or leaked executor ownership")
	}
}

func TestPauseQueueTransactionFailureDoesNotCancelWorkers(t *testing.T) {
	h, owner := newPrivateBatchHandler(t)
	queue, err := h.batchTaskManager.CreateBatchQueue("atomic pause", "", "eino_single", "manual", "", "", nil, 1, 0,
		batchTaskInputs("unit task"), database.BatchQueueCreateOptions{OwnerUserID: owner})
	if err != nil {
		t.Fatal(err)
	}
	h.batchTaskManager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	h.batchTaskManager.UpdateTaskStatus(queue.ID, queue.Tasks[0].ID, BatchTaskStatusRunning, "", "")
	cancelled := false
	h.batchTaskManager.SetTaskCancel(queue.ID, queue.Tasks[0].ID, func() { cancelled = true })
	if _, err := h.db.Exec(`CREATE TRIGGER reject_pause BEFORE UPDATE ON batch_tasks
		WHEN NEW.status='paused' BEGIN SELECT RAISE(ABORT, 'pause write rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if h.batchTaskManager.PauseQueue(queue.ID) || cancelled {
		t.Fatal("failed pause changed memory or cancelled live work")
	}
	persisted, err := h.db.GetBatchQueue(queue.ID)
	current, _ := h.batchTaskManager.GetBatchQueue(queue.ID)
	if err != nil || persisted.Status != BatchQueueStatusRunning || current.Status != BatchQueueStatusRunning || current.Tasks[0].Status != BatchTaskStatusRunning {
		t.Fatalf("partial pause survived rollback: db=%+v memory=%+v err=%v", persisted, current, err)
	}
}

func TestPausedTaskReusesConversationAndEvidenceHistory(t *testing.T) {
	h, owner := newPrivateBatchHandler(t)
	queue := &BatchTaskQueue{}
	task := &BatchTask{Message: "original task example.com"}
	id, _, resumed, err := h.prepareBatchSubTaskConversation(queue, task, owner, database.RBACScopeAssigned, "")
	if err != nil || resumed {
		t.Fatalf("fresh conversation failed: id=%s resumed=%v err=%v", id, resumed, err)
	}
	if _, err := h.db.AddMessage(id, "user", task.Message, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.AddMessage(id, "assistant", "prior evidence and next unresolved step", nil); err != nil {
		t.Fatal(err)
	}
	task.ConversationID, task.ResumeFromPause = id, true
	continuedID, history, resumed, err := h.prepareBatchSubTaskConversation(queue, task, owner, database.RBACScopeAssigned, "")
	evidenceRetained := false
	for _, message := range history {
		if message.Content == "prior evidence and next unresolved step" {
			evidenceRetained = true
		}
	}
	if err != nil || !resumed || continuedID != id || len(history) != 2 || !evidenceRetained {
		t.Fatalf("pause restarted from scratch: id=%s history=%+v resumed=%v err=%v", continuedID, history, resumed, err)
	}
}

func TestLateCancelRegistrationCannotRestartPausedTask(t *testing.T) {
	manager := NewBatchTaskManager(zap.NewNop())
	queue, _ := manager.CreateBatchQueue("late registration", "", "eino_single", "manual", "", "", nil, 1, 0, batchTaskInputs("unit"))
	manager.UpdateQueueStatus(queue.ID, BatchQueueStatusRunning)
	task, _ := manager.ClaimNextPendingTask(queue.ID)
	if !manager.PauseQueue(queue.ID) {
		t.Fatal("pause failed")
	}
	cancelled := false
	manager.SetTaskCancel(queue.ID, task.ID, func() { cancelled = true })
	manager.UpdateTaskStatus(queue.ID, task.ID, BatchTaskStatusRunning, "", "")
	current, _ := manager.GetBatchQueue(queue.ID)
	if !cancelled || current.Tasks[0].Status != BatchTaskStatusPaused {
		t.Fatal("late worker registration ignored pause")
	}
}
