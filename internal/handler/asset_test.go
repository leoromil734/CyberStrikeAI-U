package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestAssetHandlerLinkedProjectVisibilityAndCrossUserWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-handler-relations.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}
	projectA, err := db.CreateProject(&database.Project{Name: "Owner A"})
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := db.CreateProject(&database.Project{Name: "Owner B"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", projectA.ID, "user-a"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", projectB.ID, "user-b"); err != nil {
		t.Fatal(err)
	}
	asset := &database.Asset{ProjectID: projectA.ID, Domain: "http-shared.example.com", IP: "192.0.2.80", Port: 443, Protocol: "https", Source: "dns", Title: "Original"}
	if _, err := db.UpsertAssets([]*database.Asset{asset}, "user-a"); err != nil {
		t.Fatal(err)
	}
	linked := &database.Asset{ProjectID: projectB.ID, Domain: asset.Domain, IP: "192.0.2.81", Port: 443, Protocol: "https", Source: "fofa"}
	if _, err := db.UpsertAssets([]*database.Asset{linked}, "user-a", true); err != nil {
		t.Fatal(err)
	}
	h := NewAssetHandler(db, zap.NewNop())
	call := func(session security.Session, method, url, body, id string, fn gin.HandlerFunc) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(security.ContextSessionKey, session)
		c.Request = httptest.NewRequest(method, url, strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		if id != "" {
			c.Params = gin.Params{{Key: "id", Value: id}}
		}
		fn(c)
		return w
	}
	owner := security.Session{UserID: "user-a", Scope: database.RBACScopeOwn}
	foreign := security.Session{UserID: "user-b", Scope: database.RBACScopeOwn}
	listURL := "/api/assets?project_id=" + projectB.ID + "&ip=192.0.2.81"
	w := call(owner, http.MethodGet, listURL, "", "", h.List)
	var payload struct {
		Assets []*database.Asset `json:"assets"`
		Total  int               `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != http.StatusOK || payload.Total != 1 || len(payload.Assets) != 1 || payload.Assets[0].ProjectID != projectA.ID {
		t.Fatalf("HTTP linked-project query failed/lost primary: %d %s %v", w.Code, w.Body.String(), err)
	}
	w = call(foreign, http.MethodGet, listURL, "", "", h.List)
	payload.Assets, payload.Total = nil, -1
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || w.Code != http.StatusOK || payload.Total != 0 {
		t.Fatalf("HTTP relationship widened authorization: %d %s %v", w.Code, w.Body.String(), err)
	}
	body := fmt.Sprintf(`{"assets":[{"project_id":%q,"domain":%q,"port":443,"protocol":"https","ip":"192.0.2.99","title":"Hijacked"}]}`, projectB.ID, asset.Domain)
	w = call(foreign, http.MethodPost, "/api/assets/import", body, "", h.Import)
	var imported database.AssetImportResult
	if err := json.Unmarshal(w.Body.Bytes(), &imported); err != nil || w.Code != http.StatusOK || imported.Skipped != 1 || imported.Created != 0 || imported.Updated != 0 {
		t.Fatalf("HTTP conflict bypassed owner: %d %s %v", w.Code, w.Body.String(), err)
	}
	body = fmt.Sprintf(`{"project_id":%q,"domain":%q,"port":443,"protocol":"https","title":"Hijacked"}`, projectB.ID, asset.Domain)
	w = call(foreign, http.MethodPut, "/api/assets/"+asset.ID, body, asset.ID, h.Update)
	if w.Code == http.StatusOK {
		t.Fatalf("HTTP cross-user update succeeded: %s", w.Body.String())
	}
	body = fmt.Sprintf(`{"assets":[{"project_id":%q,"domain":"foreign-http-create.example.com"}]}`, projectA.ID)
	w = call(foreign, http.MethodPost, "/api/assets/import", body, "", h.Import)
	if w.Code != http.StatusForbidden {
		t.Fatalf("HTTP import wrote foreign project: %d %s", w.Code, w.Body.String())
	}
	saved, err := db.GetAsset(asset.ID, database.RBACListAccess{Scope: database.RBACScopeAll})
	if err != nil || saved.Title != "Original" || saved.ProjectID != projectA.ID || saved.IP != asset.IP {
		t.Fatalf("rejected HTTP mutations changed service: %#v %v", saved, err)
	}
	if _, total, err := db.ListAssetObservations(asset.ID, 20, 0, database.RBACListAccess{Scope: database.RBACScopeAll}); err != nil || total != 2 {
		t.Fatalf("rejected HTTP mutations left evidence: total=%d %v", total, err)
	}
}

func TestAssetListPaginatesWithinProject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "asset-list-pagination.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitAssetRelationsTables(); err != nil {
		t.Fatal(err)
	}

	project, err := db.CreateProject(&database.Project{Name: "Paged Project", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	otherProject, err := db.CreateProject(&database.Project{Name: "Other Project", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}

	assets := make([]*database.Asset, 0, 8)
	for i := 1; i <= 7; i++ {
		assets = append(assets, &database.Asset{
			ProjectID: project.ID,
			IP:        fmt.Sprintf("192.0.2.%d", i),
			Port:      80,
			Protocol:  "http",
		})
	}
	assets = append(assets, &database.Asset{
		ProjectID: otherProject.ID,
		IP:        "198.51.100.1",
		Port:      443,
		Protocol:  "https",
	})
	if _, err := db.UpsertAssets(assets, "", true); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/api/assets", NewAssetHandler(db, zap.NewNop()).List)
	request := httptest.NewRequest(http.MethodGet, "/api/assets?project_id="+project.ID+"&page=2&page_size=3", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Assets     []*database.Asset `json:"assets"`
		Total      int               `json:"total"`
		Page       int               `json:"page"`
		PageSize   int               `json:"page_size"`
		TotalPages int               `json:"total_pages"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Total != 7 || payload.Page != 2 || payload.PageSize != 3 || payload.TotalPages != 3 {
		t.Fatalf("unexpected pagination: total=%d page=%d page_size=%d total_pages=%d",
			payload.Total, payload.Page, payload.PageSize, payload.TotalPages)
	}
	if len(payload.Assets) != 3 {
		t.Fatalf("expected 3 assets on page 2, got %d", len(payload.Assets))
	}
	for _, asset := range payload.Assets {
		if asset.ProjectID != project.ID {
			t.Fatalf("asset from another project leaked into page: %#v", asset)
		}
	}
}
