package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestWebshellSecretsPublicCopy(t *testing.T) {
	conn := &database.WebShellConnection{ID: "saved", URL: "https://shell.example/test", Password: "test-password", Remark: "public", Encoding: "gbk", OS: "windows"}
	public := publicWebshellConnection(conn)
	if public.Password != maskedSecret || conn.Password != "test-password" || public.URL != conn.URL || public.OS != conn.OS || public.Encoding != conn.Encoding {
		t.Fatal("public copy leaked or changed live connection")
	}
	if publicWebshellConnection(nil) != nil || publicWebshellConnection(&database.WebShellConnection{}).Password != "" {
		t.Fatal("empty connection/password semantics changed")
	}
}

func TestWebshellSecretsResponsesAndMaskedSave(t *testing.T) {
	db, user, allowed, hidden := setupWebshellRBACTest(t)
	allowed.Password = "test-only-webshell-password"
	if err := db.UpdateWebshellConnection(allowed); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	w := performWebshellJSON(user, http.MethodGet, "/connections", nil, h.ListConnections)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), allowed.Password) || !strings.Contains(w.Body.String(), maskedSecret) {
		t.Fatalf("unsafe list status: %d", w.Code)
	}
	update := func(id string) gin.HandlerFunc {
		return func(c *gin.Context) { c.Params = gin.Params{{Key: "id", Value: id}}; h.UpdateConnection(c) }
	}
	for _, tc := range []struct{ id, url string }{{hidden.ID, hidden.URL}, {allowed.ID, "http://attacker.example"}} {
		w = performWebshellJSON(user, http.MethodPut, "/connections/"+tc.id, map[string]interface{}{"url": tc.url, "password": maskedSecret}, update(tc.id))
		if w.Code != http.StatusForbidden {
			t.Fatal("masked password reused without matching authorized connection and URL")
		}
	}
	for _, password := range []string{maskedSecret, "test-only-new-password", ""} {
		w = performWebshellJSON(user, http.MethodPut, "/connections/"+allowed.ID, map[string]interface{}{"url": allowed.URL, "password": password, "remark": "edited", "encoding": "gbk", "os": "windows"}, update(allowed.ID))
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "test-only-") {
			t.Fatalf("unsafe update: %d %s", w.Code, w.Body.String())
		}
		saved, err := db.GetWebshellConnection(allowed.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := password
		if password == maskedSecret {
			want = allowed.Password
		}
		if saved.Password != want || saved.Encoding != "gbk" || saved.OS != "windows" {
			t.Fatal("password preservation/replacement/clear or public fields regressed")
		}
	}
	w = performWebshellJSON(user, http.MethodPost, "/connections", map[string]interface{}{"url": allowed.URL, "password": maskedSecret}, h.CreateConnection)
	if w.Code != http.StatusBadRequest {
		t.Fatal("new connection stored a password marker")
	}
	w = performWebshellJSON(user, http.MethodPost, "/connections", map[string]interface{}{"url": allowed.URL, "password": "test-only-created-password"}, h.CreateConnection)
	var created database.WebShellConnection
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if w.Code != http.StatusOK || created.Password != maskedSecret || strings.Contains(w.Body.String(), "test-only-") {
		t.Fatal("creation returned a password")
	}
	saved, err := db.GetWebshellConnection(created.ID)
	if err != nil || saved == nil || saved.Password != "test-only-created-password" {
		t.Fatal("creation did not persist the real credential")
	}
}

func TestWebshellSecretsExecAndFileUseAuthorizedStoredPassword(t *testing.T) {
	db, user, allowed, _ := setupWebshellRBACTest(t)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		if r.Form.Get("pass") != "test-only-stored" {
			t.Error("executor sent a marker/wrong password")
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()
	allowed.URL, allowed.Password, allowed.OS = server.URL, "test-only-stored", "linux"
	if err := db.UpdateWebshellConnection(allowed); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	for _, handler := range []gin.HandlerFunc{h.Exec, h.FileOp} {
		body := map[string]interface{}{"url": allowed.URL, "connection_id": allowed.ID, "password": maskedSecret, "command": "echo OK", "action": "list", "os": "linux"}
		w := performWebshellJSON(user, http.MethodPost, "/exec", body, handler)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
			t.Fatalf("saved request failed: %d %s", w.Code, w.Body.String())
		}
		delete(body, "connection_id")
		w = performWebshellJSON(user, http.MethodPost, "/exec", body, handler)
		if w.Code != http.StatusBadRequest {
			t.Fatal("ad hoc marker was accepted")
		}
	}
	if calls != 2 {
		t.Fatalf("unexpected requests: %d", calls)
	}
}

func TestWebshellSecretsNetworkErrorsAndRedirects(t *testing.T) {
	_, user, _, _ := setupWebshellRBACTest(t)
	h := NewWebShellHandler(zap.NewNop(), nil)
	for _, handler := range []gin.HandlerFunc{h.Exec, h.FileOp} {
		w := performWebshellJSON(user, http.MethodPost, "/exec", map[string]interface{}{
			"url": "http://127.0.0.1:1/test", "password": "test-only-secret&special", "method": "get", "os": "linux", "command": "echo OK", "action": "list",
		}, handler)
		if strings.Contains(w.Body.String(), "test-only-") || strings.Contains(w.Body.String(), "pass=") {
			t.Fatal("request error disclosed GET password")
		}
	}
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	_ = performWebshellJSON(user, http.MethodPost, "/exec", map[string]interface{}{"url": redirect.URL, "password": "test-only-secret", "command": "echo OK"}, h.Exec)
	if leaked {
		t.Fatal("redirect forwarded a WebShell password")
	}
}
