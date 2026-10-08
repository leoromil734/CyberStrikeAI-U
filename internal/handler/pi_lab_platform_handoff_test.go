package handler

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/pilab"
)

func TestPILabPlatformPreparedAssistantMessageID(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	if run.AssistantMessageID == "" {
		t.Fatal("recovery metadata missing assistant message ID")
	}
	var conversationID, role, content string
	if err := f.db.QueryRow("SELECT conversation_id, role, content FROM messages WHERE id = ?", run.AssistantMessageID).Scan(&conversationID, &role, &content); err != nil {
		t.Fatal(err)
	}
	if conversationID != run.Platform.ConversationID || role != "assistant" || content != piPlatformPreparingMessage {
		t.Fatalf("recovery metadata references wrong placeholder: %q %q %q", conversationID, role, content)
	}
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec"})
	if err != nil || reply == nil || reply.IsError {
		t.Fatal(reply, err)
	}
	record, err := f.db.GetToolExecution(reply.ExecutionID)
	if err != nil || record.Arguments["source_message_id"] != run.AssistantMessageID {
		t.Fatal("execution and recovery message identities differ", record, err)
	}
}

func TestPILabPlatformLoadSkillTrustedDirectory(t *testing.T) {
	f := newPIPlatformFixture(t)
	f.cfg.SkillsDir = filepath.Join(filepath.Dir(f.cfg.SkillsDir), "skills with spaces")
	piPlatformWriteFixture(t, filepath.Join(f.cfg.SkillsDir, "pentest-agent-os", "SKILL.md"), "---\nname: pentest-agent-os\ndescription: Offline fixture\n---\nRun scripts/fixture.py only through the registered tool.\n")
	run := f.prepare(t)
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "load_skill", Arguments: map[string]interface{}{"name": "pentest-agent-os"}})
	if err != nil || reply == nil || reply.IsError {
		t.Fatal(reply, err)
	}
	dir, err := filepath.Abs(filepath.Join(f.cfg.SkillsDir, "pentest-agent-os"))
	if err != nil {
		t.Fatal(err)
	}
	encodedDir, _ := json.Marshal(dir)
	text := piPlatformReplyText(reply)
	for _, expected := range []string{string(encodedDir), "只读", "exec", "scripts/fixture.py"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("load_skill omitted trusted directory/instructions %q: %s", expected, text)
		}
	}
	if strings.Contains(text, f.session.Token) || strings.Contains(text, f.cfg.OpenAI.APIKey) {
		t.Fatal("skill response leaked credentials")
	}
}

func TestPILabPlatformArgumentsPreserveTargetPayload(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	payload := map[string]interface{}{
		"project_id": "target-business-project", "conversation_id": "target-thread",
		"source_conversation_id": "target-source", "source_message_id": "target-message",
		"owner_user_id": "target-user", "execution_id": "target-job",
		"records": []interface{}{map[string]interface{}{"projectId": 123, "source_execution_id": "target-execution", "authenticated_user_id": nil}},
	}
	args := map[string]interface{}{"data": payload, "headers": map[string]interface{}{"project_id": "target-header"}}
	original, _ := json.Marshal(args)
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec", Arguments: args})
	if err != nil || reply == nil || reply.IsError {
		t.Fatal("legitimate target JSON was rejected", reply, err)
	}
	record, err := f.db.GetToolExecution(reply.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(payload)
	got, _ := json.Marshal(record.Arguments["data"])
	if string(got) != string(want) {
		t.Fatalf("target JSON mutated: got %s, want %s", got, want)
	}
	after, _ := json.Marshal(args)
	if string(original) != string(after) {
		t.Fatal("caller arguments mutated")
	}
	if record.ConversationID != run.Platform.ConversationID || record.OwnerUserID != f.session.UserID || record.Arguments["project_id"] != f.project.ID || record.Arguments["source_message_id"] != run.AssistantMessageID {
		t.Fatal("nested payload affected platform routing", record)
	}
	for _, key := range []string{"project_id", "projectId", "source-project-id", "conversation_id", "source_conversation_id", "source_message_id", "owner_user_id", "authenticated_user_id", "execution_id", "sourceExecutionId", "source-execution-id"} {
		reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec", Arguments: map[string]interface{}{key: "foreign", "data": payload}})
		if !errors.Is(err, pilab.ErrForbidden) || reply != nil {
			t.Fatalf("top-level routing override admitted for %s: %+v %v", key, reply, err)
		}
	}
	var nested interface{} = "leaf"
	for i := 0; i < 34; i++ {
		nested = map[string]interface{}{"data": nested}
	}
	if _, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec", Arguments: map[string]interface{}{"data": nested}}); err == nil {
		t.Fatal("nested business payload bypassed depth limit")
	}
	if _, err := run.Execute(context.Background(), pilab.ToolCall{Name: "exec", Arguments: map[string]interface{}{"data": strings.Repeat("x", 1<<20)}}); err == nil {
		t.Fatal("business payload bypassed size limit")
	}
}
