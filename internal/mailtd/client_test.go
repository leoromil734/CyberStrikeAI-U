package mailtd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/time/rate"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	c := New("td_fixture_only")
	c.baseURL = server.URL
	c.requests = rate.NewLimiter(rate.Inf, 1)
	c.creates = rate.NewLimiter(rate.Inf, 1)
	return c
}
func TestDocumentedMailboxMessageFlow(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer td_fixture_only" {
			t.Error("missing bearer auth")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/domains":
			fmt.Fprint(w, `{"domains":[{"id":"d","domain":"mail.example","default":true}]}`)
		case "POST /api/accounts":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["address"] != "controlled@mail.example" || body["password"] != "fixture-password" {
				t.Errorf("unexpected request: %v", body)
			}
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":"account-1","address":"controlled@mail.example"}`)
		case "GET /api/accounts/account-1":
			fmt.Fprint(w, `{"id":"account-1","address":"controlled@mail.example"}`)
		case "GET /api/accounts/account-1/messages":
			if r.URL.Query().Get("page") != "2" {
				t.Error("page not forwarded")
			}
			fmt.Fprint(w, `{"messages":[{"id":"message-1","sender":"site@example.invalid","subject":"Verify","created_at":"2026-10-08T00:00:00Z"}],"page":2}`)
		case "GET /api/accounts/account-1/messages/message-1":
			fmt.Fprint(w, `{"id":"message-1","text_body":"Code: 123456","html_body":"<b>Code</b>"}`)
		case "DELETE /api/accounts/account-1":
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected endpoint %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	if d, err := c.Domains(ctx); err != nil || len(d) != 1 {
		t.Fatalf("domains: %v %v", d, err)
	}
	account, err := c.Create(ctx, "controlled@mail.example", "fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Account(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	if page, err := c.Messages(ctx, account.ID, 2); err != nil || len(page.Messages) != 1 {
		t.Fatalf("messages: %v %v", page, err)
	}
	if message, err := c.Read(ctx, account.ID, "message-1"); err != nil || message.Text != "Code: 123456" {
		t.Fatalf("read: %v %v", message, err)
	}
	if err := c.Delete(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	if calls != 6 {
		t.Fatalf("unexpected calls: %d", calls)
	}
}
func TestProviderFailuresNeverEchoSecretsOrFollowRedirects(t *testing.T) {
	for _, status := range []int{401, 403, 429, 503, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/must-not-follow")
				w.Header().Set("Retry-After", "45")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"message":"td_fixture_only fixture-password"}`)
			})
			_, err := c.Create(context.Background(), "a@mail.example", "fixture-password")
			if err == nil || strings.Contains(err.Error(), "td_fixture_only") || strings.Contains(err.Error(), "fixture-password") {
				t.Fatalf("unsafe error: %v", err)
			}
			if calls != 1 {
				t.Fatalf("POST/redirect unexpectedly retried: %d", calls)
			}
		})
	}
}
func TestResponseBoundsAndInvalidJSON(t *testing.T) {
	for _, body := range []string{"<html>upstream failed</html>", strings.Repeat("x", maxResponseBytes+1)} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := c.Domains(context.Background()); err == nil {
			t.Fatal("invalid/oversized response accepted")
		}
	}
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("invalid identifier reached network") })
	for _, id := range []string{"../other", "a/b", "", "user?token=x", "a\\b"} {
		if _, err := c.Messages(context.Background(), id, 1); err == nil {
			t.Error("invalid ID accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Domains(ctx); err == nil {
		t.Fatal("cancel ignored")
	}
}
func TestSecretFileEnvironmentAndNoCredentialSerialization(t *testing.T) {
	t.Setenv("MAILTD_API_KEY", "")
	t.Setenv("MAILTD_API_KEY_FILE", "")
	if client, err := FromEnvironment(); err != nil || client != nil {
		t.Fatal("unconfigured provider must be disabled")
	}
	path := filepath.Join(t.TempDir(), "mailtd.key")
	if err := os.WriteFile(path, []byte("td_file_fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAILTD_API_KEY_FILE", path)
	client, err := FromEnvironment()
	if err != nil || client == nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(client)
	if strings.Contains(string(data), "td_file_fixture") {
		t.Fatal("API key serialized")
	}
	t.Setenv("MAILTD_API_KEY_FILE", path+"-missing")
	if _, err := FromEnvironment(); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("unsafe missing file error")
	}
}
