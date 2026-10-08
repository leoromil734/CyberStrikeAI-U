package handler

import (
	"errors"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/pilab"
)

func recoveryFixtureRun(t *testing.T, f *piPlatformFixture, prepared *pilab.PreparedRun) pilab.Run {
	t.Helper()
	assessment, err := f.db.LatestAssessmentRun(prepared.Platform.ConversationID)
	if err != nil || assessment == nil {
		t.Fatal(assessment, err)
	}
	messages, err := f.db.GetMessages(prepared.Platform.ConversationID)
	if err != nil || len(messages) < 2 {
		t.Fatal(messages, err)
	}
	if prepared.AssistantMessageID == "" {
		t.Fatal("platform preparation did not publish its exact assistant message identity")
	}
	return pilab.Run{ID: assessment.AssessmentID, Mode: pilab.ModePlatform, ProjectID: f.project.ID, ConversationID: prepared.Platform.ConversationID, AssistantMessageID: prepared.AssistantMessageID, Status: "interrupted"}
}

func TestPILabRecoveryStopsOnlyOriginalMetadataWithoutReplay(t *testing.T) {
	f := newPIPlatformFixture(t)
	prepared := f.prepare(t)
	run := recoveryFixtureRun(t, f, prepared)
	_, _ = f.db.AddMessage(run.ConversationID, "user", "later user message", nil)
	newer, err := f.db.AddMessage(run.ConversationID, "assistant", "KEEP_NEWER_RESPONSE", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.platform.Recover(f.session.UserID, &run); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(run.Report, "未自动重跑") {
		t.Fatal(run.Report)
	}
	assessment, err := f.db.LatestAssessmentRun(run.ConversationID)
	if err != nil || assessment.Status != "cancelled" || assessment.CompletionReason != "pi_service_interrupted" {
		t.Fatal(assessment, err)
	}
	messages, err := f.db.GetMessages(run.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if message.ID == run.AssistantMessageID && !strings.Contains(message.Content, "未自动重跑") {
			t.Fatal(message.Content)
		}
		if message.ID == newer.ID && message.Content != "KEEP_NEWER_RESPONSE" {
			t.Fatal("new message overwritten")
		}
	}
	var calls int
	if err = f.db.QueryRow("SELECT count(*) FROM tool_executions WHERE conversation_id = ?", run.ConversationID).Scan(&calls); err != nil || calls != 0 {
		t.Fatal("recovery executed tools", calls, err)
	}
}

func TestPILabRecoveryPreservesDurablyFinalizedDelivery(t *testing.T) {
	f := newPIPlatformFixture(t)
	prepared := f.prepare(t)
	run := recoveryFixtureRun(t, f, prepared)
	assessment, _ := f.db.LatestAssessmentRun(run.ConversationID)
	if err := f.db.UpdateAssistantMessageFinalize(run.AssistantMessageID, "DURABLE_REPORT", []string{"recorded-execution"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.db.FinishAssessmentRun(assessment.ID, "completed", "verified_before_exit", "completed"); err != nil {
		t.Fatal(err)
	}
	if err := f.platform.Recover(f.session.UserID, &run); err != nil {
		t.Fatal(err)
	}
	if run.Status != "completed" || run.Report != "DURABLE_REPORT" || len(run.ExecutionIDs) != 1 {
		t.Fatal(run)
	}
}

func TestPILabRecoveryRejectsChangedBindings(t *testing.T) {
	f := newPIPlatformFixture(t)
	prepared := f.prepare(t)
	run := recoveryFixtureRun(t, f, prepared)
	if err := f.platform.Recover("foreign-owner", &run); !errors.Is(err, pilab.ErrForbidden) {
		t.Fatal(err)
	}
	other, err := f.db.CreateConversation("other fixture", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	message, err := f.db.AddMessage(other.ID, "assistant", "UNRELATED_MESSAGE", nil)
	if err != nil {
		t.Fatal(err)
	}
	run.AssistantMessageID = message.ID
	if err := f.platform.Recover(f.session.UserID, &run); !errors.Is(err, pilab.ErrForbidden) {
		t.Fatal(err)
	}
	messages, _ := f.db.GetMessages(other.ID)
	if len(messages) != 1 || messages[0].Content != "UNRELATED_MESSAGE" {
		t.Fatal(messages)
	}
	assessment, _ := f.db.LatestAssessmentRun(run.ConversationID)
	if assessment.Status != "running" {
		t.Fatal("foreign binding changed assessment")
	}
}
