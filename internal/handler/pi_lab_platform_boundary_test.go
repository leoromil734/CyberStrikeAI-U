package handler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/pilab"
)

func TestPILabPlatformHardlinksDenied(t *testing.T) {
	f := newPIPlatformFixture(t)
	run := f.prepare(t)
	private := filepath.Join(t.TempDir(), "private.txt")
	piPlatformWriteFixture(t, private, "PRIVATE_HARDLINK_SENTINEL")
	link := filepath.Join(run.Platform.Workspace, "hardlink.txt")
	if err := os.Link(private, link); err != nil {
		t.Fatalf("create hardlink fixture: %v", err)
	}
	for _, name := range []string{"read_file", "write_file"} {
		t.Run(name, func(t *testing.T) {
			reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: name, Arguments: map[string]interface{}{"path": link, "content": "overwrite"}})
			if err != nil || reply == nil || !reply.IsError || strings.Contains(piPlatformReplyText(reply), "PRIVATE_HARDLINK_SENTINEL") {
				t.Fatalf("hardlink escaped: %+v %v", reply, err)
			}
			data, err := os.ReadFile(private)
			if err != nil || string(data) != "PRIVATE_HARDLINK_SENTINEL" {
				t.Fatal("outside file changed or truncated", err)
			}
		})
	}
	skillLink := filepath.Join(f.cfg.SkillsDir, "pentest-agent-os", "references", "hardlink.md")
	if err := os.Link(private, skillLink); err != nil {
		t.Fatal(err)
	}
	reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: "read_skill_file", Arguments: map[string]interface{}{"name": "pentest-agent-os", "path": "references/hardlink.md"}})
	if err != nil || reply == nil || !reply.IsError || strings.Contains(piPlatformReplyText(reply), "PRIVATE_HARDLINK_SENTINEL") {
		t.Fatal("skill hardlink escaped", reply, err)
	}
}

func TestPILabPlatformGetVulnerabilityProjectBoundary(t *testing.T) {
	permissions := append(append([]string(nil), piPlatformTestPermissions...), "vulnerability:read")
	f := newPIPlatformFixture(t, permissions...)
	if _, err := f.db.UpsertRBACRole(f.roleID, "pi-tester", "", database.RBACScopeAll, permissions); err != nil {
		t.Fatal(err)
	}
	f.platform.config.mu.Lock()
	role := f.cfg.Roles[piPlatformRole]
	role.Tools = append(role.Tools, builtin.ToolGetVulnerability)
	f.cfg.Roles[piPlatformRole] = role
	f.platform.config.mu.Unlock()
	var calls atomic.Int32
	f.server.RegisterTool(mcp.Tool{Name: builtin.ToolGetVulnerability, InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"id": map[string]interface{}{"type": "string"}}, "required": []string{"id"}}}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		calls.Add(1)
		vuln, err := f.db.GetVulnerability(args["id"].(string))
		if err != nil {
			return nil, err
		}
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: vuln.Description}}}, nil
	})
	run := f.prepare(t)
	principal, ok := authctx.PrincipalFromContext(run.Context)
	if !ok || !principal.HasPermission("vulnerability:read") || principal.ScopeFor("vulnerability:read") != database.RBACScopeAll {
		t.Fatal("fixture must have global vulnerability read access")
	}
	other, err := f.db.CreateProject(&database.Project{Name: "other project"})
	if err != nil {
		t.Fatal(err)
	}
	conversation := func(projectID string) string {
		t.Helper()
		conv, err := f.db.CreateConversation("boundary fixture", database.ConversationCreateMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.SetConversationProjectID(conv.ID, projectID); err != nil {
			t.Fatal(err)
		}
		return conv.ID
	}
	ownConversation := conversation(f.project.ID)
	otherConversation := conversation(other.ID)
	unboundConversation := conversation("")
	for _, tc := range []struct {
		name, project, conversation string
		allow                       bool
	}{
		{"own_project", f.project.ID, "", true},
		{"own_conversation", f.project.ID, ownConversation, true},
		{"legacy_current_conversation", "", run.Platform.ConversationID, true},
		{"legacy_same_project", "", ownConversation, true},
		{"other_project", other.ID, "", false},
		{"other_conversation", other.ID, otherConversation, false},
		{"legacy_other_project", "", otherConversation, false},
		{"conflicting_project", other.ID, run.Platform.ConversationID, false},
		{"conflicting_conversation", f.project.ID, otherConversation, false},
		{"unbound", "", "", false},
		{"unbound_conversation", "", unboundConversation, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vuln, err := f.db.CreateVulnerability(&database.Vulnerability{ProjectID: tc.project, ConversationID: tc.conversation, Title: "fixture", Description: "VULNERABILITY_PRIVATE_SENTINEL", Severity: "info"})
			if err != nil {
				t.Fatal(err)
			}
			// CreateVulnerability fills project_id from the conversation; clear it
			// explicitly to exercise historical records without project attribution.
			if tc.project == "" {
				if _, err := f.db.Exec("UPDATE vulnerabilities SET project_id = NULL WHERE id = ?", vuln.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := calls.Load()
			reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: builtin.ToolGetVulnerability, Arguments: map[string]interface{}{"id": " " + vuln.ID + " "}})
			if tc.allow {
				if err != nil || reply == nil || reply.IsError || calls.Load() != before+1 || piPlatformReplyText(reply) != "VULNERABILITY_PRIVATE_SENTINEL" {
					t.Fatalf("same-project read failed: %+v %v", reply, err)
				}
			} else if !errors.Is(err, pilab.ErrForbidden) || reply != nil || calls.Load() != before {
				t.Fatalf("out-of-project record reached MCP: %+v %v", reply, err)
			}
		})
	}
	t.Run("conversation_rebound_after_read", func(t *testing.T) {
		convID := conversation(f.project.ID)
		vuln, err := f.db.CreateVulnerability(&database.Vulnerability{ProjectID: f.project.ID, ConversationID: convID, Title: "rebound fixture", Severity: "info"})
		if err != nil {
			t.Fatal(err)
		}
		call := pilab.ToolCall{Name: builtin.ToolGetVulnerability, Arguments: map[string]interface{}{"id": vuln.ID}}
		if reply, err := run.Execute(context.Background(), call); err != nil || reply == nil || reply.IsError {
			t.Fatal("initial same-project read failed", reply, err)
		}
		if err := f.db.SetConversationProjectID(convID, other.ID); err != nil {
			t.Fatal(err)
		}
		before := calls.Load()
		if reply, err := run.Execute(context.Background(), call); !errors.Is(err, pilab.ErrForbidden) || reply != nil || calls.Load() != before {
			t.Fatal("rebound conversation was not rechecked", reply, err)
		}
	})
	for _, id := range []interface{}{nil, "", "missing-vulnerability", 12} {
		before := calls.Load()
		reply, err := run.Execute(context.Background(), pilab.ToolCall{Name: builtin.ToolGetVulnerability, Arguments: map[string]interface{}{"id": id}})
		if !errors.Is(err, pilab.ErrForbidden) || reply != nil || calls.Load() != before {
			t.Fatalf("unverifiable ID reached MCP: %+v %v", reply, err)
		}
	}
}
