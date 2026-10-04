package handler

import (
	"context"
	"fmt"
	"time"
)

// Tool termination and offline result ingestion are different barriers. Waiting
// here avoids asking a model to repair a ledger while its originals are queued.
func (h *AgentHandler) waitFinalizationIngestion(ctx context.Context, conversationID string, progress func(string, string, interface{})) error {
	if h == nil || h.db == nil || conversationID == "" {
		return nil
	}
	deadline, notified := finalizationToolWaitDeadline(ctx), false
	for {
		if err := agentRunContextError(ctx); err != nil {
			return err
		}
		var pending int
		err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM result_ingestion_jobs
 WHERE conversation_id = ? AND state = 'pending'
 AND assessment_id = (SELECT assessment_id FROM assessment_runs WHERE conversation_id = ? ORDER BY started_at DESC, id DESC LIMIT 1)`, conversationID, conversationID).Scan(&pending)
		if err != nil {
			return fmt.Errorf("无法核实本轮原件入库状态: %w", err)
		}
		if pending == 0 {
			return nil
		}
		if !notified && progress != nil {
			progress("finalization_waiting_evidence", fmt.Sprintf("工具结果仍有 %d 项等待持久化解析，完成后继续核对覆盖与报告…", pending), map[string]interface{}{"conversationId": conversationID, "pendingIngestions": pending, "source": "finalizer"})
			notified = true
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(finalizationPendingPollInterval):
		}
	}
}
