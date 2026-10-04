package multiagent

import (
	"strings"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// deepToolsWithExit is the Eino v0.8.13 equivalent of ChatModelAgentConfig.Exit:
// deep.Config has no Exit field. Register the native tool AND ReturnDirectly so
// the graph stops after its successful tool result. Add it after tool-search
// splitting, keeping the submission tool visible. Copy shared containers so the
// supervisor, plan-execute executor and configured specialist tools are unchanged.
func deepToolsWithExit(cfg adk.ToolsConfig) adk.ToolsConfig {
	cfg.Tools = append(append([]tool.BaseTool(nil), cfg.Tools...), &adk.ExitTool{})
	direct := make(map[string]bool, len(cfg.ReturnDirectly)+1)
	for name, enabled := range cfg.ReturnDirectly {
		direct[name] = enabled
	}
	direct[adk.ToolInfoExit.Name] = true
	cfg.ReturnDirectly = direct
	return cfg
}

// Only historical draft recovery uses this provenance marker. It must NEVER be
// used to set RunResult.ReportSubmitted: persisted messages are not live events.
const rootExitReportExtraKey = "cyberstrike_root_exit_report_v1"

// einoReportSubmission is local to one runEinoADKAgentLoop invocation. In
// particular, coverage-repair segments and new user requests start empty even
// when their base history contains a successful exit from the same request.
// Retries retain only submissions actually observed during this invocation.
type einoReportSubmission struct {
	rootName  string
	paths     map[string]bool // exact ADK paths reached by the root or its native transfers
	submitted bool
	report    string
}

func newEinoReportSubmission(rootName, mode string) *einoReportSubmission {
	path := []string{rootName}
	if mode == "supervisor" {
		// v0.8.13 wraps the supervisor's flowAgent in a same-named container.
		// Runner adds the outer step; the inner flowAgent adds the second.
		path = append(path, rootName)
	}
	return &einoReportSubmission{rootName: rootName, paths: map[string]bool{strings.Join(path, "\x00"): true}}
}

// observe accepts only a completed native exit result with an Exit action on
// a proven ADK root path. AgentName alone is insufficient: nested agents may
// share the root's name and plan_execute streams several non-root roles as main.
// Supervisor transfer paths are admitted only after their successful native
// transfer event; an arbitrary child path ending with the root name is not root.
// The tool body, not the assistant tool-call arguments, is authoritative.
func (s *einoReportSubmission) observe(ev *adk.AgentEvent, msg *schema.Message, recvErr error) *schema.Message {
	if s == nil || ev == nil || msg == nil || recvErr != nil || ev.Err != nil ||
		ev.Action == nil || s.rootName == "" || len(ev.RunPath) == 0 ||
		msg.Role != schema.Tool || strings.TrimSpace(msg.ToolCallID) == "" ||
		einoToolResultIsError(msg.ToolName, strings.TrimSpace(msg.Content)) {
		return msg
	}
	parts := make([]string, len(ev.RunPath))
	for i := range ev.RunPath {
		parts[i] = ev.RunPath[i].String()
	}
	key := strings.Join(parts, "\x00")
	root, known := s.paths[key]
	if !known || ev.AgentName != parts[len(parts)-1] {
		return msg
	}
	if transfer := ev.Action.TransferToAgent; transfer != nil && msg.ToolName == adk.TransferToAgentToolName && transfer.DestAgentName != "" {
		s.paths[key+"\x00"+transfer.DestAgentName] = transfer.DestAgentName == s.rootName
	}
	if !root || ev.AgentName != s.rootName || !ev.Action.Exit || msg.ToolName != adk.ToolInfoExit.Name {
		return msg
	}
	s.submitted = true
	s.report = msg.Content
	// Preserve the source message and all existing metadata. The copy may be
	// appended to the persisted terminal tool pair for later draft recovery.
	copyMsg := *msg
	copyMsg.Extra = make(map[string]any, len(msg.Extra)+1)
	for key, value := range msg.Extra {
		copyMsg.Extra[key] = value
	}
	copyMsg.Extra[rootExitReportExtraKey] = true
	return &copyMsg
}

func historicalRootExitReport(msg *schema.Message) string {
	if msg == nil || msg.Role != schema.Tool || msg.ToolName != adk.ToolInfoExit.Name ||
		einoToolResultIsError(msg.ToolName, strings.TrimSpace(msg.Content)) {
		return ""
	}
	if root, _ := msg.Extra[rootExitReportExtraKey].(bool); !root {
		return ""
	}
	return strings.TrimSpace(msg.Content)
}
