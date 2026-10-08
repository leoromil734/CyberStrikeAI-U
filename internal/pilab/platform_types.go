package pilab

import "context"

const ModeProbe = "probe"
const ModePlatform = "platform"

type SkillInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

type BridgeConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// PlatformInput is a per-run snapshot, passed only through stdin. Neither role
// instructions nor bridge credentials are persisted in a public Run record.
type PlatformInput struct {
	RoleName           string           `json:"role_name"`
	Instructions       string           `json:"instructions"`
	WorkerInstructions string           `json:"worker_instructions"`
	ProjectID          string           `json:"project_id"`
	ConversationID     string           `json:"conversation_id"`
	Workspace          string           `json:"workspace"`
	Skills             []SkillInfo      `json:"skills"`
	Tools              []ToolDefinition `json:"tools"`
	Bridge             *BridgeConfig    `json:"bridge,omitempty"`
}

type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
	AgentID   string                 `json:"agent_id"`
}

type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolReply struct {
	Content     []ToolContent `json:"content"`
	IsError     bool          `json:"is_error"`
	ExecutionID string        `json:"execution_id,omitempty"`
}

type ToolExecutor func(context.Context, ToolCall) (*ToolReply, error)

// PreparedRun is supplied by trusted application code, never by HTTP input or
// the model. Context carries the immutable principal/workspace/conversation.
// Start registers the lifecycle; Finish may downgrade completion after checking
// platform evidence, then persists the report and finishes the platform task.
// Close must cancel this run's detached tool executions, never other runs.
type PreparedRun struct {
	AssistantMessageID string
	Context            context.Context
	Platform           *PlatformInput
	Execute            ToolExecutor
	Start              func(context.Context, context.CancelFunc) error
	Finish             func(*Run) error
	Close              func()
}

type PrepareFunc func(context.Context, string, CreateRequest) (*PreparedRun, error)

type Profile struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Role      struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"role"`
	Skills []SkillInfo      `json:"skills"`
	Tools  []ToolDefinition `json:"tools"`
	Limits Limits           `json:"limits"`
}
