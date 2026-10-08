package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/pilab"

	"github.com/google/uuid"
)

type piPlatformTool struct {
	definition pilab.ToolDefinition
	name       string
	external   bool
}

var piPlatformSharedTools = []string{
	builtin.ToolTemporaryEmail, builtin.ToolUpsertFindingCandidate, builtin.ToolListFindingCandidates,
	builtin.ToolGetToolExecution, builtin.ToolWaitToolExecution, builtin.ToolCancelToolExecution,
	builtin.ToolListResultArtifacts, builtin.ToolReadResultArtifact, builtin.ToolAssembleResultEvidence,
	builtin.ToolQueryReconInventory, builtin.ToolRegisterResultArtifact,
}

// Catalog filtering is an additional restriction, not a substitute for the
// authorizers installed on Server/ExternalMCPManager.CallTool.
func piPlatformToolPermission(p authctx.Principal, name string) bool {
	permission := "agent:local-execute"
	switch name {
	case builtin.ToolTemporaryEmail, builtin.ToolAnalyzeImage:
		permission = "agent:execute"
	case builtin.ToolUpsertProjectFact, builtin.ToolDeprecateProjectFact, builtin.ToolRestoreProjectFact, builtin.ToolUpsertFindingCandidate:
		permission = "project:write"
	case builtin.ToolGetProjectFact, builtin.ToolListProjectFacts, builtin.ToolSearchProjectFacts, builtin.ToolListFindingCandidates:
		permission = "project:read"
	case builtin.ToolRecordVulnerability:
		permission = "vulnerability:write"
	case builtin.ToolListVulnerabilities, builtin.ToolGetVulnerability:
		permission = "vulnerability:read"
	case builtin.ToolListKnowledgeRiskTypes, builtin.ToolSearchKnowledgeBase:
		permission = "knowledge:read"
	case builtin.ToolSearchExperience, builtin.ToolGetExperience:
		permission = "experience:read"
	case builtin.ToolProposeExperience, builtin.ToolObserveExperience:
		permission = "experience:write"
	case builtin.ToolGetToolExecution, builtin.ToolWaitToolExecution, builtin.ToolListResultArtifacts, builtin.ToolReadResultArtifact, builtin.ToolAssembleResultEvidence, builtin.ToolQueryReconInventory:
		permission = "monitor:read"
	case builtin.ToolCancelToolExecution:
		permission = "monitor:write"
	case builtin.ToolRegisterResultArtifact:
		return p.HasPermission("monitor:read") && p.HasPermission("monitor:write")
	case builtin.ToolQueryAssets, builtin.ToolGetAsset:
		permission = "asset:read"
	case builtin.ToolCreateAsset, builtin.ToolUpdateAsset, builtin.ToolCompleteAssetScan:
		permission = "asset:write"
	case builtin.ToolDeleteAsset:
		permission = "asset:delete"
	default:
		// Management/C2 tools are never implicitly introduced by this adapter.
		// Unsupported builtins fail closed rather than inherit local-execute.
		if builtin.IsBuiltinTool(name) {
			return false
		}
	}
	return p.HasPermission(permission)
}

func (p *PILabPlatform) tools(ctx context.Context, role config.RoleConfig, principal authctx.Principal) (map[string]piPlatformTool, error) {
	roleAllowed := map[string]bool{}
	allow := map[string]bool{}
	for _, name := range role.Tools {
		allow[name], roleAllowed[name] = true, true
	}
	for _, name := range piPlatformSharedTools {
		allow[name] = true
	}
	out := map[string]piPlatformTool{}
	for _, tool := range p.server.GetAllTools() {
		if !allow[tool.Name] || !piPlatformToolPermission(principal, tool.Name) || piPlatformFileTool(tool.Name) {
			continue
		}
		definition, err := piPlatformDefinition(tool)
		if err != nil {
			continue
		}
		out[definition.Name] = piPlatformTool{definition: definition, name: tool.Name}
	}
	if p.external != nil && principal.HasPermission("mcp:external:execute") && principal.ScopeFor("mcp:external:execute") == database.RBACScopeAll {
		// An external tool must be explicitly named by the role; do not expand
		// a deprecated MCP-server wildcard or add shared external tools.
		wantExternal := false
		for _, name := range role.Tools {
			wantExternal = wantExternal || strings.Contains(name, "::")
		}
		if wantExternal {
			tools, err := p.external.GetAllTools(ctx)
			if err != nil && len(out) == 0 {
				return nil, err
			}
			for _, tool := range tools {
				if !allow[tool.Name] || !p.externalEnabled(tool.Name) {
					continue
				}
				definition, err := piPlatformDefinition(tool)
				if err != nil {
					continue
				}
				definition.Name = strings.ReplaceAll(tool.Name, "::", "__")
				if _, exists := out[definition.Name]; exists || piPlatformFileTool(definition.Name) {
					continue
				}
				out[definition.Name] = piPlatformTool{definition: definition, name: tool.Name, external: true}
			}
		}
	}
	for _, tool := range out {
		if roleAllowed[tool.name] {
			return out, nil
		}
	}
	return nil, fmt.Errorf("渗透测试角色白名单没有可调用的已注册工具")
}

func (p *PILabPlatform) externalEnabled(name string) bool {
	parts := strings.SplitN(name, "::", 2)
	if len(parts) != 2 || p.external == nil {
		return false
	}
	cfg, ok := p.external.GetConfigs()[parts[0]]
	if !ok || !cfg.ExternalMCPEnable || cfg.Disabled {
		return false
	}
	if enabled, set := cfg.ToolEnabled[parts[1]]; set && !enabled {
		return false
	}
	return true
}

func piPlatformDefinition(tool mcp.Tool) (pilab.ToolDefinition, error) {
	// Round-trip strips Go-specific schema types. Do not send handler pointers,
	// runtime config, or default/example values containing operator secrets.
	data, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return pilab.ToolDefinition{}, err
	}
	var schema map[string]interface{}
	if err = json.Unmarshal(data, &schema); err != nil {
		return pilab.ToolDefinition{}, err
	}
	if schema == nil {
		schema = map[string]interface{}{}
	}
	piPlatformSchema(schema)
	schema["type"] = "object"
	if _, ok := schema["properties"].(map[string]interface{}); !ok {
		schema["properties"] = map[string]interface{}{}
	}
	description := tool.ShortDescription
	if description == "" {
		description = tool.Description
	}
	return pilab.ToolDefinition{Name: tool.Name, Description: description, InputSchema: schema}, nil
}
func piPlatformSchema(value interface{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		delete(v, "default")
		delete(v, "examples")
		// Go nil slices serialize as null, which model providers reject for
		// JSON Schema required. Absence means no required properties.
		if required, exists := v["required"]; exists && required == nil {
			delete(v, "required")
		}
		if kind, ok := v["type"].(string); ok {
			switch kind {
			case "int", "int64", "int32":
				v["type"] = "integer"
			case "float", "float64", "float32":
				v["type"] = "number"
			case "bool":
				v["type"] = "boolean"
			}
		}
		for _, item := range v {
			piPlatformSchema(item)
		}
	case []interface{}:
		for _, item := range v {
			piPlatformSchema(item)
		}
	}
}
func piPlatformToolDefinitions(tools map[string]piPlatformTool) []pilab.ToolDefinition {
	out := make([]pilab.ToolDefinition, 0, len(tools))
	for _, tool := range tools {
		out = append(out, tool.definition)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Use Manager's per-call cancellation with trusted run values. This also keeps
// the one AgentRunBudget shared by coordinator/workers, rather than allocating
// a fresh fact-write budget on each bridge call.
type piPlatformCallContext struct {
	context.Context
	values context.Context
}

func (c piPlatformCallContext) Value(key interface{}) interface{} { return c.values.Value(key) }

func (s *piPlatformRun) execute(ctx context.Context, call pilab.ToolCall) (*pilab.ToolReply, error) {
	if ctx == nil {
		return nil, pilab.ErrForbidden
	}
	s.mu.Lock()
	limit := s.request.MaxToolCalls
	if limit <= 0 || limit > pilab.PlatformLimitCaps.MaxToolCalls {
		limit = pilab.DefaultPlatformLimits.MaxToolCalls
	}
	if s.closed || !s.started || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, context.Canceled
	}
	if s.callCount >= limit {
		s.mu.Unlock()
		return nil, fmt.Errorf("PI 工具调用预算已用完")
	}
	s.callCount++
	s.inFlight++
	s.calls.Add(1)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.inFlight--; s.mu.Unlock(); s.calls.Done() }()
	principal, err := s.authorize()
	if err != nil {
		s.stop(err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Merge cancellation explicitly: even if a caller accidentally supplies a
	// Background context, closing this run still interrupts Server.Wait.
	callCtx, cancel := context.WithCancel(piPlatformCallContext{Context: ctx, values: s.ctx})
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	callCtx = authctx.WithPrincipal(callCtx, principal)
	args, err := s.arguments(call.Arguments)
	if err != nil {
		return nil, err
	}
	if piPlatformFileTool(call.Name) {
		// File/skill bridges have their own rooted implementation, but still
		// publish begin/end records through the platform's native-tool monitor
		// and its existing result observer. They never invoke a shell/executor.
		id := s.platform.server.BeginToolExecution(callCtx, call.Name, args)
		callCtx = mcp.WithMCPExecutionID(callCtx, id)
		s.RegisterRunningTool(s.conversationID, id)
		defer s.UnregisterRunningTool(s.conversationID, id)
		result, invokeErr := s.fileTool(callCtx, call.Name, args)
		if invokeErr == nil {
			invokeErr = callCtx.Err()
		}
		if invokeErr != nil {
			result = &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: invokeErr.Error()}}, IsError: true}
		}
		s.platform.server.FinishToolExecution(callCtx, id, call.Name, args, mcp.ToolResultPlainText(result), invokeErr)
		// Reuse the monitor's canonical result instead of spilling the original
		// a second time while the result pipeline may already be hashing it.
		if recorded, ok := s.platform.server.GetExecution(id); ok && recorded.Result != nil {
			canonical := *recorded.Result
			canonical.IsError = invokeErr != nil
			result = &canonical
		}
		return s.boundedReply(result, id), nil
	}
	tool, allowed := s.tools[call.Name]
	if !allowed {
		return nil, fmt.Errorf("%w：工具不在当前角色白名单中", pilab.ErrForbidden)
	}
	if tool.external {
		if !principal.HasPermission("mcp:external:execute") || principal.ScopeFor("mcp:external:execute") != database.RBACScopeAll || !s.platform.externalEnabled(tool.name) {
			return nil, pilab.ErrForbidden
		}
	} else if !piPlatformToolPermission(principal, tool.name) {
		return nil, pilab.ErrForbidden
	}
	if !tool.external && tool.name == builtin.ToolGetVulnerability {
		if err := s.authorizeVulnerability(args); err != nil {
			return nil, err
		}
	}
	// Identity arguments are injected only where the registered schema declares
	// them. Context-only tools need no extra arguments and retain strict schemas.
	properties, _ := tool.definition.InputSchema["properties"].(map[string]interface{})
	for key := range properties {
		if value, reserved := s.identityValue(key); reserved {
			args[key] = value
		}
	}
	var result *mcp.ToolResult
	var id string
	if tool.external {
		result, id, err = s.platform.external.CallTool(callCtx, tool.name, args)
	} else {
		result, id, err = s.platform.server.CallTool(callCtx, tool.name, args)
	}
	if id != "" {
		s.mu.Lock()
		s.executions[id] = true
		s.mu.Unlock()
	}
	if err != nil {
		// Preserve the execution identity even for failed/cancelled waits; the
		// authoritative detailed error and output remain in platform storage.
		result = &mcp.ToolResult{IsError: true, Content: []mcp.Content{{Type: "text", Text: "MCP 工具调用失败：" + err.Error()}}}
	}
	if result == nil {
		result = &mcp.ToolResult{IsError: true, Content: []mcp.Content{{Type: "text", Text: "工具没有返回可读取结果"}}}
	}
	return s.boundedReply(result, id), nil
}

// Global vulnerability:read is necessary but does not expand a run's project.
// Check persisted ownership, not caller-supplied project/conversation fields.
func (s *piPlatformRun) authorizeVulnerability(args map[string]interface{}) error {
	id, ok := args["id"].(string)
	id = strings.TrimSpace(id)
	if !ok || id == "" || s.request.ProjectID == "" {
		return pilab.ErrForbidden
	}
	vuln, err := s.platform.db.GetVulnerability(id)
	if err != nil || vuln == nil {
		return pilab.ErrForbidden
	}
	projectID := strings.TrimSpace(vuln.ProjectID)
	if projectID != "" && projectID != s.request.ProjectID {
		return pilab.ErrForbidden
	}
	if vuln.ConversationID != "" {
		conversationProject, err := s.platform.db.GetConversationProjectID(vuln.ConversationID)
		if err != nil || conversationProject != s.request.ProjectID {
			return pilab.ErrForbidden
		}
		projectID = conversationProject
	}
	if projectID != s.request.ProjectID {
		return pilab.ErrForbidden
	}
	args["id"] = id
	return nil
}

func (s *piPlatformRun) identityValue(key string) (string, bool) {
	switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key)) {
	case "projectid", "sourceprojectid":
		return s.request.ProjectID, true
	case "conversationid", "sourceconversationid":
		return s.conversationID, true
	case "sourcemessageid":
		return s.messageID, true
	case "owneruserid", "authenticateduserid":
		return s.owner, true
	}
	return "", false
}

func (s *piPlatformRun) arguments(input map[string]interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(input)
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("工具参数无效或超过 1 MiB")
	}
	var args map[string]interface{}
	if err = json.Unmarshal(data, &args); err != nil {
		return nil, fmt.Errorf("工具参数必须是 JSON 对象")
	}
	if args == nil {
		args = map[string]interface{}{}
	}
	var check func(interface{}, int) error
	check = func(v interface{}, depth int) error {
		if depth > 32 {
			return fmt.Errorf("工具参数嵌套过深")
		}
		switch value := v.(type) {
		case map[string]interface{}:
			for key, item := range value {
				// Only top-level arguments route platform tools. Nested objects
				// may be target HTTP bodies, headers or other opaque business data;
				// their field names do not grant platform identity or execution access.
				if want, reserved := s.identityValue(key); depth == 0 && reserved {
					if actual, ok := item.(string); !ok || actual != want {
						return fmt.Errorf("%w：禁止修改运行身份字段", pilab.ErrForbidden)
					}
				}
				normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
				if depth == 0 && (normalized == "executionid" || normalized == "sourceexecutionid") {
					id, ok := item.(string)
					s.mu.Lock()
					own := s.executions[id]
					s.mu.Unlock()
					if !ok || !own {
						return fmt.Errorf("%w：执行记录不属于本次运行", pilab.ErrForbidden)
					}
				}
				if err := check(item, depth+1); err != nil {
					return err
				}
			}
		case []interface{}:
			for _, item := range value {
				if err := check(item, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return args, check(args, 0)
}

func (s *piPlatformRun) boundedReply(result *mcp.ToolResult, id string) *pilab.ToolReply {
	spillID := id
	if spillID == "" {
		spillID = "pi-" + uuid.NewString()
	}
	result = mcp.NormalizeToolResultForStorageWithSpill(result, mcp.DefaultToolResultMaxBytes, mcp.ToolResultSpillConfig{RootDir: s.cfg.MultiAgent.EinoMiddleware.ReductionRootDir, ProjectID: s.request.ProjectID, ConversationID: s.conversationID, ExecutionID: spillID})
	return piPlatformReply(result, id)
}
func piPlatformReply(result *mcp.ToolResult, id string) *pilab.ToolReply {
	reply := &pilab.ToolReply{Content: []pilab.ToolContent{}, ExecutionID: id}
	if result == nil {
		reply.IsError = true
		return reply
	}
	reply.IsError = result.IsError
	for _, content := range result.Content {
		if content.Type == "text" {
			reply.Content = append(reply.Content, pilab.ToolContent{Type: "text", Text: content.Text})
		}
	}
	return reply
}
