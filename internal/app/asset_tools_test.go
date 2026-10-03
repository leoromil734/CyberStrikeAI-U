package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"

	"go.uber.org/zap"
)

func TestAssetToolsCRUDQueryAndPageLimit(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-tools.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateRBACUser("asset-agent", "Asset Agent", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAssigned, map[string]bool{
		"asset:read": true, "asset:write": true, "asset:delete": true,
	})
	ctx := authctx.WithPrincipal(context.Background(), principal)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerAssetTools(server, db, zap.NewNop())

	wantTools := map[string]bool{
		builtin.ToolCreateAsset: false, builtin.ToolGetAsset: false, builtin.ToolQueryAssets: false,
		builtin.ToolUpdateAsset: false, builtin.ToolDeleteAsset: false, builtin.ToolCompleteAssetScan: false,
	}
	for _, tool := range server.GetAllTools() {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, found := range wantTools {
		if !found {
			t.Fatalf("asset tool not registered: %s", name)
		}
	}

	for _, tool := range server.GetAllTools() {
		if tool.Name != builtin.ToolCreateAsset {
			continue
		}
		for _, keyword := range []string{"oneOf", "allOf", "anyOf"} {
			if _, exists := tool.InputSchema[keyword]; exists {
				t.Fatalf("create asset schema contains Bedrock-incompatible top-level %s", keyword)
			}
		}
	}

	result, _, err := server.CallTool(ctx, builtin.ToolCreateAsset, map[string]interface{}{"title": "Missing target"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("create asset accepted missing host/ip/domain: result=%#v err=%v", result, err)
	}

	result, _, err = server.CallTool(ctx, builtin.ToolCreateAsset, map[string]interface{}{
		"ip": "192.0.2.42", "port": 443, "protocol": "https", "title": "Before", "tags": []interface{}{"prod"},
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("create asset result=%#v err=%v", result, err)
	}
	assets, total, err := db.ListAssets(20, 0, database.AssetListFilter{}, database.RBACListAccess{UserID: user.ID, Scope: database.RBACScopeAssigned})
	if err != nil || total != 1 || len(assets) != 1 {
		t.Fatalf("saved assets total=%d len=%d err=%v", total, len(assets), err)
	}
	id := assets[0].ID

	result, _, err = server.CallTool(ctx, builtin.ToolUpdateAsset, map[string]interface{}{"id": id, "title": "After"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("update asset result=%#v err=%v", result, err)
	}
	updated, err := db.GetAsset(id, database.RBACListAccess{UserID: user.ID, Scope: database.RBACScopeAssigned})
	if err != nil || updated.Title != "After" || updated.IP != "192.0.2.42" {
		t.Fatalf("partial update lost fields: %#v err=%v", updated, err)
	}

	result, _, err = server.CallTool(ctx, builtin.ToolQueryAssets, map[string]interface{}{
		"sort_by": "last_scan_at", "sort_order": "asc", "page": 1, "page_size": 1,
	})
	if err != nil || result == nil || result.IsError || !strings.Contains(toolResultText(result), "第 1/1 页") || !strings.Contains(toolResultText(result), "last_scan_at=never") {
		t.Fatalf("query asset result=%#v err=%v", result, err)
	}
	result, _, err = server.CallTool(ctx, builtin.ToolQueryAssets, map[string]interface{}{"page_size": agentAssetPageSizeMax + 1})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("oversized page was accepted: result=%#v err=%v", result, err)
	}

	conversation, err := db.CreateConversation("asset scan", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser(user.ID, "conversation", conversation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateVulnerability(&database.Vulnerability{ConversationID: conversation.ID, Title: "finding", Severity: "high", Target: "192.0.2.42"}); err != nil {
		t.Fatal(err)
	}
	scanCtx := mcp.WithMCPConversationID(ctx, conversation.ID)
	result, _, err = server.CallTool(scanCtx, builtin.ToolCompleteAssetScan, map[string]interface{}{"id": id})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("complete scan result=%#v err=%v", result, err)
	}
	scanned, err := db.GetAsset(id, database.RBACListAccess{UserID: user.ID, Scope: database.RBACScopeAssigned})
	if err != nil || scanned.LastScanAt == nil || scanned.LastScanConversationID != conversation.ID || scanned.VulnerabilityCount != 1 {
		t.Fatalf("scan fields not updated: %#v err=%v", scanned, err)
	}

	result, _, err = server.CallTool(ctx, builtin.ToolDeleteAsset, map[string]interface{}{"id": id})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("delete asset result=%#v err=%v", result, err)
	}
	if _, err := db.GetAsset(id, database.RBACListAccess{Scope: database.RBACScopeAll}); err == nil {
		t.Fatal("asset still exists after delete")
	}
}

func TestAssetToolsDefaultProjectAndMultiProjectEvidence(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-default-project.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateRBACUser("asset-project-agent", "Agent", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	projectA, err := db.CreateProject(&database.Project{Name: "Default A"})
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := db.CreateProject(&database.Project{Name: "Linked B"})
	if err != nil {
		t.Fatal(err)
	}
	for _, project := range []*database.Project{projectA, projectB} {
		if err := db.SetResourceOwner("project", project.ID, user.ID); err != nil {
			t.Fatal(err)
		}
	}
	conversationA, err := db.CreateConversation("Asset A", database.ConversationCreateMeta{ProjectID: projectA.ID})
	if err != nil {
		t.Fatal(err)
	}
	conversationB, err := db.CreateConversation("Asset B", database.ConversationCreateMeta{ProjectID: projectB.ID})
	if err != nil {
		t.Fatal(err)
	}
	principal := authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeOwn, map[string]bool{"asset:read": true, "asset:write": true, "asset:delete": true})
	ctx := authctx.WithPrincipal(context.Background(), principal)
	ctxA, ctxB := mcp.WithMCPConversationID(ctx, conversationA.ID), mcp.WithMCPConversationID(ctx, conversationB.ID)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerAssetTools(server, db, zap.NewNop())

	result, _, err := server.CallTool(ctxA, builtin.ToolCreateAsset, map[string]interface{}{
		"domain": "default.example.com", "ip": "192.0.2.60", "port": 443, "protocol": "https", "source": "dns", "source_query": "original resolver",
		"observed_at": "2026-10-01T12:00:00Z", "execution_id": "exec-create-a",
	})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("default project create failed: %#v %v", result, err)
	}
	access := database.RBACListAccess{UserID: user.ID, Scope: database.RBACScopeOwn}
	assets, total, err := db.ListAssets(20, 0, database.AssetListFilter{ProjectID: projectA.ID}, access)
	if err != nil || total != 1 || len(assets) != 1 || assets[0].ProjectID != projectA.ID {
		t.Fatalf("conversation project not inherited: %#v total=%d %v", assets, total, err)
	}
	id := assets[0].ID
	observations, total, err := db.ListAssetObservations(id, 20, 0, access)
	if err != nil || total != 1 || observations[0].ConversationID != conversationA.ID || observations[0].ExecutionID != "exec-create-a" || observations[0].ObservedAt.Format("2006-01-02T15:04:05Z") != "2026-10-01T12:00:00Z" {
		t.Fatalf("create lost execution evidence: %#v total=%d %v", observations, total, err)
	}
	result, _, err = server.CallTool(ctxB, builtin.ToolCreateAsset, map[string]interface{}{
		"domain": "default.example.com", "ip": "192.0.2.61", "port": 443, "protocol": "https", "source": "fofa", "source_query": "new resolver",
	})
	if err != nil || result == nil || result.IsError || !strings.Contains(toolResultText(result), "updated") {
		t.Fatalf("create did not associate shared service with B: %#v %v", result, err)
	}
	for _, tool := range []string{builtin.ToolGetAsset, builtin.ToolQueryAssets} {
		result, _, err = server.CallTool(ctxB, tool, map[string]interface{}{"id": id})
		if err != nil || result == nil || result.IsError || !strings.Contains(toolResultText(result), id) {
			t.Fatalf("linked-project %s failed: %#v %v", tool, result, err)
		}
	}
	result, _, err = server.CallTool(ctxB, builtin.ToolGetAsset, map[string]interface{}{"id": id})
	if err != nil || result.IsError || !strings.Contains(toolResultText(result), "context_project_id") || strings.Contains(toolResultText(result), "exec-create-a") {
		t.Fatalf("project B get leaked project A observation: %#v %v", result, err)
	}
	result, _, err = server.CallTool(ctxB, builtin.ToolUpdateAsset, map[string]interface{}{"id": id, "title": "Updated in B"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("linked project update failed: %#v %v", result, err)
	}
	saved, err := db.GetAsset(id, access)
	if err != nil || saved.ProjectID != projectA.ID || saved.Title != "Updated in B" || saved.IP != "192.0.2.60" {
		t.Fatalf("shared service lost original project/IP: %#v %v", saved, err)
	}
	if _, total, err := db.ListAssetObservations(id, 20, 0, access); err != nil || total != 2 {
		t.Fatalf("metadata-only update fabricated or lost evidence: total=%d %v", total, err)
	}
	result, _, err = server.CallTool(ctxB, builtin.ToolUpdateAsset, map[string]interface{}{"id": id, "ip": "192.0.2.62", "source": "manual"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("explicit observation update failed: %#v %v", result, err)
	}
	if _, total, err := db.ListAssetObservations(id, 20, 0, access); err != nil || total != 3 {
		t.Fatalf("explicit IP update lost evidence: total=%d %v", total, err)
	}
	// A bound conversation cannot move/clear the shared service, even when
	// the caller owns both projects and the MCP authorizer permits the ID.
	for _, projectID := range []string{projectB.ID, ""} {
		assertAssetToolDenied(t, server, ctxA, builtin.ToolCreateAsset, map[string]interface{}{"domain": "denied.example.com", "project_id": projectID})
		assertAssetToolDenied(t, server, ctxA, builtin.ToolUpdateAsset, map[string]interface{}{"id": id, "project_id": projectID, "title": "must not change"})
	}
	assertAssetToolDenied(t, server, ctxA, builtin.ToolCreateAsset, map[string]interface{}{"domain": "bad-time.example.com", "observed_at": "yesterday"})
	if _, total, err := db.ListAssets(20, 0, database.AssetListFilter{}, access); err != nil || total != 1 {
		t.Fatalf("rejected tool create left partial asset: total=%d %v", total, err)
	}
	unknownCtx := mcp.WithMCPConversationID(ctx, "nonexistent-conversation")
	assertAssetToolDenied(t, server, unknownCtx, builtin.ToolCreateAsset, map[string]interface{}{"domain": "missing-conversation.example.com"})
}

func TestAssetMutationToolsEnforceProjectAndUserBoundaries(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-mutation-boundaries.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	userA, err := db.CreateRBACUser("asset-boundary-a", "A", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	userB, err := db.CreateRBACUser("asset-boundary-b", "B", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	projects := make([]*database.Project, 3)
	conversations := make([]*database.Conversation, 3)
	for i, name := range []string{"Bound A", "Other A", "Private B"} {
		projects[i], err = db.CreateProject(&database.Project{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		owner := userA.ID
		if i == 2 {
			owner = userB.ID
		}
		if err := db.SetResourceOwner("project", projects[i].ID, owner); err != nil {
			t.Fatal(err)
		}
		conversations[i], err = db.CreateConversation(name, database.ConversationCreateMeta{ProjectID: projects[i].ID})
		if err != nil {
			t.Fatal(err)
		}
	}
	assets := []*database.Asset{
		{ProjectID: projects[0].ID, Domain: "owned.example.com", Title: "Original A"},
		{ProjectID: projects[1].ID, Domain: "other-project.example.com", Title: "Other A"},
	}
	if _, err := db.UpsertAssets(assets, userA.ID); err != nil {
		t.Fatal(err)
	}
	permissions := map[string]bool{"asset:read": true, "asset:write": true, "asset:delete": true}
	principalA := authctx.NewPrincipal(userA.ID, userA.Username, database.RBACScopeOwn, permissions)
	principalB := authctx.NewPrincipal(userB.ID, userB.Username, database.RBACScopeOwn, permissions)
	ctxA := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), principalA), conversations[0].ID)
	ctxB := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), principalB), conversations[2].ID)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerAssetTools(server, db, zap.NewNop())
	// Same owner is insufficient to cross the bound conversation's project.
	for _, tool := range []string{builtin.ToolGetAsset, builtin.ToolUpdateAsset, builtin.ToolDeleteAsset, builtin.ToolCompleteAssetScan} {
		assertAssetToolDenied(t, server, ctxA, tool, map[string]interface{}{"id": assets[1].ID, "title": "escaped"})
	}
	// Global RBAC also does not disable a bound conversation's project guard.
	global := authctx.NewPrincipal("global-operator", "Operator", database.RBACScopeAll, permissions)
	globalCtx := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), global), conversations[0].ID)
	assertAssetToolDenied(t, server, globalCtx, builtin.ToolUpdateAsset, map[string]interface{}{"id": assets[1].ID, "title": "global escaped"})
	for _, tool := range []string{builtin.ToolGetAsset, builtin.ToolUpdateAsset, builtin.ToolDeleteAsset, builtin.ToolCompleteAssetScan} {
		assertAssetToolDenied(t, server, ctxB, tool, map[string]interface{}{"id": assets[0].ID, "title": "hijacked"})
	}
	assertAssetToolDenied(t, server, ctxB, builtin.ToolCreateAsset, map[string]interface{}{"domain": assets[0].Domain})
	assertAssetToolDenied(t, server, ctxB, builtin.ToolCreateAsset, map[string]interface{}{"domain": "foreign-project-write.example.com", "project_id": projects[0].ID})
	// Default inheritance must check the implicit project's authorization as
	// well, not only explicit project_id arguments checked by the authorizer.
	foreignContext := mcp.WithMCPConversationID(authctx.WithPrincipal(context.Background(), principalA), conversations[2].ID)
	assertAssetToolDenied(t, server, foreignContext, builtin.ToolCreateAsset, map[string]interface{}{"domain": "implicit-foreign.example.com"})
	for i, asset := range assets {
		saved, err := db.GetAsset(asset.ID, database.RBACListAccess{Scope: database.RBACScopeAll})
		if err != nil || saved.Title != asset.Title || saved.ProjectID != projects[i].ID || saved.LastScanAt != nil {
			t.Fatalf("rejected mutation changed an asset: %#v %v", saved, err)
		}
	}
	if _, total, err := db.ListAssets(20, 0, database.AssetListFilter{}, database.RBACListAccess{Scope: database.RBACScopeAll}); err != nil || total != 2 {
		t.Fatalf("foreign create left partial state: total=%d %v", total, err)
	}
}

func TestAssetToolsFailClosedWithoutPrincipalOrPermissions(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-tools-principal.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	asset := &database.Asset{IP: "192.0.2.100"}
	if _, err := db.UpsertAssets([]*database.Asset{asset}, "owner"); err != nil {
		t.Fatal(err)
	}
	// Asset callbacks enforce their own boundary even when a custom server
	// forgot to install the global MCP authorizer. Trusted-internal empty
	// database access must not be reachable through an unauthenticated tool.
	server := mcp.NewServer(zap.NewNop())
	registerAssetTools(server, db, zap.NewNop())
	contexts := []context.Context{
		context.Background(),
		authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("", "", database.RBACScopeAll, map[string]bool{"asset:read": true, "asset:write": true, "asset:delete": true})),
		authctx.WithPrincipal(context.Background(), authctx.NewPrincipal("owner", "Owner", database.RBACScopeAll, map[string]bool{})),
	}
	for _, ctx := range contexts {
		for _, tool := range []string{builtin.ToolCreateAsset, builtin.ToolGetAsset, builtin.ToolQueryAssets, builtin.ToolUpdateAsset, builtin.ToolDeleteAsset, builtin.ToolCompleteAssetScan} {
			assertAssetToolDenied(t, server, ctx, tool, map[string]interface{}{"id": asset.ID, "ip": "192.0.2.101", "title": "must not change"})
		}
	}
	saved, err := db.GetAsset(asset.ID, database.RBACListAccess{Scope: database.RBACScopeAll})
	if err != nil || saved.IP != "192.0.2.100" || saved.Title != "" {
		t.Fatalf("unauthenticated tool changed asset: %#v %v", saved, err)
	}
}

func assertAssetToolDenied(t *testing.T, server *mcp.Server, ctx context.Context, name string, args map[string]interface{}) {
	t.Helper()
	result, _, err := server.CallTool(ctx, name, args)
	if err == nil && result != nil && !result.IsError {
		t.Fatalf("%s unexpectedly succeeded: %s", name, toolResultText(result))
	}
	if err == nil && result == nil {
		t.Fatalf("%s returned no error and no result", name)
	}
}

func toolResultText(result *mcp.ToolResult) string {
	var b strings.Builder
	if result == nil {
		return ""
	}
	for _, content := range result.Content {
		b.WriteString(content.Text)
	}
	return b.String()
}

func TestAssetReadToolsRespectConversationProjectScope(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-project-scope.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}

	projectA, err := db.CreateProject(&database.Project{Name: "Project A"})
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := db.CreateProject(&database.Project{Name: "Project B"})
	if err != nil {
		t.Fatal(err)
	}
	assets := []*database.Asset{
		{ProjectID: projectA.ID, IP: "192.0.2.10", Protocol: "https"},
		{ProjectID: projectB.ID, IP: "192.0.2.20", Protocol: "https"},
		{IP: "192.0.2.30", Protocol: "https"},
	}
	if result, err := db.UpsertAssets(assets, "", true); err != nil || result.Created != len(assets) {
		t.Fatalf("seed assets result=%#v err=%v", result, err)
	}

	bound, err := db.CreateConversation("bound", database.ConversationCreateMeta{ProjectID: projectA.ID})
	if err != nil {
		t.Fatal(err)
	}
	unbound, err := db.CreateConversation("unbound", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	principal := authctx.NewPrincipal("admin", "admin", database.RBACScopeAll, map[string]bool{"asset:read": true})
	ctx := authctx.WithPrincipal(context.Background(), principal)
	server := mcp.NewServer(zap.NewNop())
	server.SetToolAuthorizer(mcpToolAuthorizer(db))
	registerAssetTools(server, db, zap.NewNop())

	boundCtx := mcp.WithMCPConversationID(ctx, bound.ID)
	result, _, err := server.CallTool(boundCtx, builtin.ToolQueryAssets, map[string]interface{}{})
	text := toolResultText(result)
	if err != nil || result == nil || result.IsError || !strings.Contains(text, assets[0].ID) || strings.Contains(text, assets[1].ID) || strings.Contains(text, assets[2].ID) {
		t.Fatalf("bound query escaped project scope: result=%#v text=%q err=%v", result, text, err)
	}

	// Even an explicit foreign project_id cannot override the conversation boundary.
	result, _, err = server.CallTool(boundCtx, builtin.ToolQueryAssets, map[string]interface{}{"project_id": projectB.ID})
	text = toolResultText(result)
	if err != nil || result == nil || result.IsError || !strings.Contains(text, assets[0].ID) || strings.Contains(text, assets[1].ID) {
		t.Fatalf("project_id overrode conversation scope: result=%#v text=%q err=%v", result, text, err)
	}

	result, _, err = server.CallTool(boundCtx, builtin.ToolGetAsset, map[string]interface{}{"id": assets[1].ID})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("bound get read a foreign-project asset: result=%#v err=%v", result, err)
	}

	unboundCtx := mcp.WithMCPConversationID(ctx, unbound.ID)
	result, _, err = server.CallTool(unboundCtx, builtin.ToolQueryAssets, map[string]interface{}{"page_size": 10})
	text = toolResultText(result)
	if err != nil || result == nil || result.IsError || !strings.Contains(text, assets[0].ID) || !strings.Contains(text, assets[1].ID) || !strings.Contains(text, assets[2].ID) {
		t.Fatalf("unbound query did not retain all-assets behavior: result=%#v text=%q err=%v", result, text, err)
	}
}
