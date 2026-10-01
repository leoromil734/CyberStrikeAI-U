package handler

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestActiveTaskModelsUsePerConversationRunRecords(t *testing.T) {
	db, _ := setupConversationRBACTest(t)
	var tasks []*AgentTask
	for _, spec := range []struct{ channel, model string }{{"channel-a", "model-a"}, {"channel-b", "model-b"}, {"", ""}} {
		conv, err := db.CreateConversation("task", database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if spec.channel != "" {
			if err := db.SetConversationAIChannel(conv.ID, spec.channel, spec.model); err != nil {
				t.Fatal(err)
			}
		}
		tasks = append(tasks, &AgentTask{ConversationID: conv.ID})
	}
	tasks = append(tasks, nil, &AgentTask{})
	attachAgentTaskAIModels(db, tasks)
	if tasks[0].AIModel != "model-a" || tasks[0].AIChannelID != "channel-a" || tasks[1].AIModel != "model-b" || tasks[1].AIChannelID != "channel-b" {
		t.Fatalf("concurrent tasks lost their actual model records: %+v %+v", tasks[0], tasks[1])
	}
	if tasks[2].AIModel != "" || tasks[2].AIChannelID != "" || tasks[4].AIModel != "" {
		t.Fatal("unrecorded task incorrectly assigned a default model")
	}
	attachAgentTaskAIModels(nil, tasks)
	attachAgentTaskAIModels(db, nil)
}

func TestActiveTaskListModelEnrichmentPreservesAccessAndSnapshots(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, user := setupConversationRBACTest(t)
	manager := &AgentTaskManager{tasks: make(map[string]*AgentTask)}
	var allowedIDs []string
	for i, spec := range []struct{ channel, model string }{{"channel-a", "model-a"}, {"channel-b", "model-b"}, {"hidden-channel", "hidden-model"}} {
		conv, err := db.CreateConversation("task title", database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SetConversationAIChannel(conv.ID, spec.channel, spec.model); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			if err := db.AssignResourceToUser(user.ID, "conversation", conv.ID); err != nil {
				t.Fatal(err)
			}
			allowedIDs = append(allowedIDs, conv.ID)
		}
		manager.tasks[conv.ID] = &AgentTask{ConversationID: conv.ID, Message: "task prompt", Status: "running", StartedAt: time.Now(), AgentMode: "eino_single"}
	}
	h := &AgentHandler{db: db, tasks: manager, logger: zap.NewNop()}
	response := performConversationRequest(user, http.MethodGet, "/api/agent-loop/tasks", nil, h.ListAgentTasks)
	if response.Code != http.StatusOK {
		t.Fatalf("list returned %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Tasks []*AgentTask `json:"tasks"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Tasks) != 2 {
		t.Fatalf("list leaked inaccessible tasks: %s", response.Body.String())
	}
	want := map[string]string{allowedIDs[0]: "model-a", allowedIDs[1]: "model-b"}
	for _, task := range payload.Tasks {
		if task.AIModel != want[task.ConversationID] || task.AIChannelID == "" || task.Title != "task title" || task.Status != "running" {
			t.Fatalf("missing task metadata: %+v", task)
		}
	}
	for _, task := range manager.tasks {
		if task.AIModel != "" || task.AIChannelID != "" {
			t.Fatal("list enrichment mutated shared running-task state")
		}
	}
	// Changing one conversation's channel must not change another task's model.
	if err := db.SetConversationAIChannel(allowedIDs[0], "channel-c", "model-c"); err != nil {
		t.Fatal(err)
	}
	response = performConversationRequest(user, http.MethodGet, "/api/agent-loop/tasks", nil, h.ListAgentTasks)
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want[allowedIDs[0]] = "model-c"
	for _, task := range payload.Tasks {
		if task.AIModel != want[task.ConversationID] {
			t.Fatalf("stale/default model used: %+v", task)
		}
	}
}
