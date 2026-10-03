package handler

import (
	"cyberstrike-ai/internal/agentfinalizer"
	"testing"
)

func TestDeduplicateBatchInputsKeepsDifferentModelsAndExactConstraints(t *testing.T) {
	out, skipped := deduplicateBatchTaskInputs([]BatchTaskInput{
		{Message: "test https://example.com/a?id=1", AIChannelID: "one"},
		{Message: "test https://example.com/a?id=1", AIChannelID: "one"},
		{Message: "test https://example.com/a?id=1", AIChannelID: "two"},
		{Message: "test https://example.com/a?id=2", AIChannelID: "one"},
	})
	if skipped != 1 || len(out) != 3 {
		t.Fatalf("dedup destroyed distinct requests: %d %+v", skipped, out)
	}
}

func TestDeclinedBatchDeliveryCannotBecomeCompleted(t *testing.T) {
	d := batchSubTaskDeliveryDecision(nil, agentfinalizer.Decision{Status: agentfinalizer.StatusDeclined, CompletionReason: agentfinalizer.ReasonDeclined, Finalizable: true, Finalized: true})
	if d.Status == BatchTaskStatusCompleted || d.EvidenceVerified {
		t.Fatalf("decline counted as success: %+v", d)
	}
}
