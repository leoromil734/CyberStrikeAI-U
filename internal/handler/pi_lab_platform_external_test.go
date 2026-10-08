package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/pilab"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

// A loopback-only MCP stub verifies the real external manager/SDK path. It
// returns fixture strings or waits for cancellation; it cannot execute commands
// or contact a target/model/provider.
func TestPILabPlatformExternalExplicitRolePermissionAndCancellation(t *testing.T) {
	f := newPIPlatformFixture(t)
	stub := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "pi-offline-fixture", Version: "1"}, nil)
	stopped := make(chan struct{}, 1)
	for _, name := range []string{"echo", "slow", "unlisted", "disabled"} {
		toolName := name
		stub.AddTool(&sdkmcp.Tool{Name: name, InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"project_id": map[string]interface{}{"type": "string"}, "conversation_id": map[string]interface{}{"type": "string"}}}}, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
			if strings.Contains(string(req.Params.Arguments), f.session.Token) {
				t.Error("login token reached external MCP")
			}
			if toolName == "slow" {
				select {
				case <-ctx.Done():
					stopped <- struct{}{}
					return nil, ctx.Err()
				case <-time.After(10 * time.Second):
					return nil, errors.New("fixture cancelled too late")
				}
			}
			var args map[string]interface{}
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, err
			}
			if args["project_id"] != f.project.ID || args["conversation_id"] == "" {
				return nil, errors.New("missing locked identity")
			}
			return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: "external-fixture"}}}, nil
		})
	}
	transport := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return stub }, nil)
	local := httptest.NewServer(transport)
	t.Cleanup(func() {
		for session := range stub.Sessions() {
			_ = session.Close()
		}
		local.Close()
	})
	external := mcp.NewExternalMCPManagerWithStorage(zap.NewNop(), f.db)
	external.ConfigureToolWaitTimeoutSeconds(1)
	external.LoadConfigs(&config.ExternalMCPConfig{Servers: map[string]config.ExternalMCPServerConfig{"fixture": {Type: "http", URL: local.URL, ExternalMCPEnable: true, Timeout: 3, ToolEnabled: map[string]bool{"disabled": false}}}})
	var authorized atomic.Int32
	external.SetToolAuthorizer(func(ctx context.Context, name string, _ map[string]interface{}) error {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok || !principal.HasPermission("mcp:external:execute") || principal.ScopeFor("mcp:external:execute") != database.RBACScopeAll || mcp.MCPProjectIDFromContext(ctx) != f.project.ID || mcp.MCPConversationIDFromContext(ctx) == "" {
			return errors.New("external authorizer denied")
		}
		authorized.Add(1)
		return nil
	})
	if err := external.StartClient("fixture"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = external.StopClient("fixture") })
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		client, ok := external.GetClient("fixture")
		if ok && client.IsConnected() {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("loopback MCP fixture did not initialize")
		case <-tick.C:
		}
	}
	f.platform.external = external
	f.platform.config.mu.Lock()
	role := f.cfg.Roles[piPlatformRole]
	role.Tools = append(role.Tools, "fixture::echo", "fixture::slow", "fixture::disabled")
	f.cfg.Roles[piPlatformRole] = role
	f.platform.config.mu.Unlock()
	profileNames := func() map[string]bool {
		t.Helper()
		c, w := f.ginContext()
		f.platform.Profile(c)
		var profile pilab.Profile
		if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, tool := range profile.Tools {
			names[tool.Name] = true
		}
		return names
	}
	if profileNames()["fixture__echo"] {
		t.Fatal("external tools exposed without permission")
	}
	permissions := append(append([]string(nil), piPlatformTestPermissions...), "mcp:external:execute")
	if _, err := f.db.UpsertRBACRole(f.roleID, "pi-tester", "", database.RBACScopeOwn, permissions); err != nil {
		t.Fatal(err)
	}
	if profileNames()["fixture__echo"] {
		t.Fatal("external own scope accepted")
	}
	if _, err := f.db.UpsertRBACRole(f.roleID, "pi-tester", "", database.RBACScopeAll, permissions); err != nil {
		t.Fatal(err)
	}
	names := profileNames()
	if !names["fixture__echo"] || !names["fixture__slow"] || names["fixture__unlisted"] || names["fixture__disabled"] {
		t.Fatalf("external whitelist/enable filter: %+v", names)
	}
	run := f.prepare(t)
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "fixture__echo"})
	if err != nil || reply.IsError || reply.ExecutionID == "" || piPlatformReplyText(reply) != "external-fixture" {
		t.Fatalf("external execution: %+v %v", reply, err)
	}
	record, err := f.db.GetToolExecution(reply.ExecutionID)
	if err != nil || record.ToolName != "fixture::echo" || record.ConversationID != run.Platform.ConversationID || record.OwnerUserID != f.session.UserID || authorized.Load() != 1 {
		t.Fatalf("external monitor identity: %+v %v", record, err)
	}
	if _, err = run.Execute(context.Background(), pilab.ToolCall{Name: "fixture__unlisted"}); !errors.Is(err, pilab.ErrForbidden) {
		t.Fatal("unlisted external tool admitted")
	}
	reply, err = run.Execute(context.Background(), pilab.ToolCall{Name: "fixture__slow"})
	if err != nil || reply.ExecutionID == "" {
		t.Fatal("external background execution not tracked", err)
	}
	run.Close()
	finalRecord, readErr := f.db.GetToolExecution(reply.ExecutionID)
	if readErr != nil || finalRecord.Status == mcp.ToolExecutionStatusRunning || finalRecord.Status == mcp.ToolExecutionStatusQueued {
		t.Fatalf("close returned before detached execution persistence: %+v %v", finalRecord, readErr)
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("external detached execution leaked")
	}
}
