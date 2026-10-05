package coverage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/evidence"
)

const frameworkFixture = "===== Prepared Request =====\nMethod: GET\nURL: https://example.invalid/api?x=1\nHeaders (1 total):\n  host: example.invalid\nBody: <empty>\n\n===== Response #1 =====\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":true}\n\n----- Meta #1 -----\nRedirects: 0\nWall Time (client): 0.001000s\nEncoding Used: utf-8 (declared)\n"
const frameworkInput = `{"url":"https://example.invalid/api?x=1","method":"GET","include_headers":true}`

type originalStore struct {
	executions map[string]evidence.Execution
	artifacts  map[string]evidence.Artifact
}

func (s *originalStore) RecordExecution(ctx context.Context, e evidence.Execution) error {
	if err := e.Validate(ctx); err != nil {
		return err
	}
	s.executions[e.ID] = e
	return nil
}
func (s *originalStore) ResultExecution(ctx context.Context, id string) (evidence.Execution, error) {
	e, ok := s.executions[id]
	if !ok {
		return e, evidence.ErrDenied
	}
	return e, e.Access.Authorize(ctx)
}
func (s *originalStore) RegisterArtifact(ctx context.Context, v evidence.VerifiedArtifact) (evidence.Artifact, error) {
	a, err := v.Metadata()
	if err != nil {
		return a, err
	}
	if err = a.Access.Authorize(ctx); err != nil {
		return a, err
	}
	s.artifacts[a.ID] = a
	return a, nil
}
func (s *originalStore) ResultArtifact(ctx context.Context, id string) (evidence.Artifact, error) {
	a, ok := s.artifacts[id]
	if !ok {
		return a, evidence.ErrDenied
	}
	return a, a.Access.Authorize(ctx)
}
func (s *originalStore) ResultArtifacts(ctx context.Context, id string, limit, offset int) ([]evidence.Artifact, error) {
	if _, err := s.ResultExecution(ctx, id); err != nil {
		return nil, err
	}
	var out []evidence.Artifact
	for _, a := range s.artifacts {
		if a.ExecutionID == id {
			out = append(out, a)
		}
	}
	return out, nil
}

func originalFixture(t *testing.T, tool, input, output string) (context.Context, *evidence.Registry, *originalStore, OriginalBinding, evidence.Artifact, evidence.Artifact) {
	t.Helper()
	dir := t.TempDir()
	b := OriginalBinding{Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "u"}, AssessmentID: "assessment", ScopeID: "scope"}
	ctx := evidence.WithAccess(context.Background(), b.Access)
	now := time.Now()
	e := evidence.Execution{ID: "execution-1", Access: b.Access, AssessmentID: b.AssessmentID, ScopeID: b.ScopeID, Tool: tool, Status: "completed", Completion: evidence.Complete, StartedAt: now, FinishedAt: now, OutputBytes: int64(len(output))}
	store := &originalStore{executions: map[string]evidence.Execution{e.ID: e}, artifacts: map[string]evidence.Artifact{}}
	registry, err := evidence.NewRegistry(store, []evidence.ManagedRoot{{Path: dir, Access: e.Access, ExecutionID: e.ID, Files: []string{"input.json", "output.txt"}}}, MaxHTTPOriginalBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { registry.Close() })
	save := func(name, kind, data string) evidence.Artifact {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		a, err := registry.Register(ctx, e, evidence.Candidate{Path: path, Kind: kind, Format: "text", Completion: evidence.Complete})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	return ctx, registry, store, b, save("input.json", "input", input), save("output.txt", "output", output)
}

func TestVerifyHTTPOriginalBindingAndIntegrity(t *testing.T) {
	for _, test := range []string{"valid", "owner", "project", "conversation", "assessment", "scope", "hash", "input-hash", "metadata-hash", "unsafe-path", "unfinished", "partial", "capped", "timeout", "artifact-binding", "input-as-output", "output-size", "missing-finish", "forged-parser-tool", "zero-token"} {
		t.Run(test, func(t *testing.T) {
			ctx, r, s, b, in, out := originalFixture(t, "http-framework-test", frameworkInput, frameworkFixture)
			e := s.executions[in.ExecutionID]
			switch test {
			case "owner":
				b.Owner = "other"
			case "project":
				b.ProjectID = "other"
			case "conversation":
				b.ConversationID = "other"
			case "assessment":
				b.AssessmentID = "other"
			case "scope":
				b.ScopeID = "other"
			case "hash":
				if err := os.WriteFile(out.Path, []byte(frameworkFixture+"changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "input-hash":
				if err := os.WriteFile(in.Path, []byte(`{"url":"https://other.invalid"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "metadata-hash":
				out.SHA256 = strings.Repeat("0", 64)
				s.artifacts[out.ID] = out
			case "unsafe-path":
				out.Path = filepath.Join(filepath.Dir(out.Path), "..", "output.txt")
				s.artifacts[out.ID] = out
			case "unfinished":
				e.Status = "running"
			case "partial":
				e.Completion = evidence.Partial
			case "capped":
				e.Capped = true
			case "timeout":
				e.TimedOut = true
			case "artifact-binding":
				out.ExecutionID = "foreign"
				s.artifacts[out.ID] = out
			case "input-as-output":
				out.ID = in.ID
			case "output-size":
				e.OutputBytes++
			case "missing-finish":
				e.FinishedAt = time.Time{}
			case "forged-parser-tool":
				e.Tool = "read_file"
				e.ParserTool = "http-framework-test"
			case "zero-token":
				if (HTTPObservation{}).Matches("https://example.invalid/api?x=1", "GET") {
					t.Fatal("forged zero observation matched")
				}
				return
			}
			s.executions[e.ID] = e
			observation, err := VerifyHTTPOriginal(ctx, r, b, e.ID, in.ID, out.ID)
			if test != "valid" {
				if err == nil {
					t.Fatal("invalid original accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !observation.Matches("https://EXAMPLE.invalid:443/api?x=1", "GET") || observation.StatusCode() != 200 || !strings.Contains(observation.EvidenceRef(), out.SHA256) {
				t.Fatalf("valid exchange lost: %+v", observation)
			}
			for _, target := range []struct{ url, method string }{{"https://other.invalid/api?x=1", "GET"}, {"https://example.invalid/Api?x=1", "GET"}, {"https://example.invalid/api?x=2", "GET"}, {"https://example.invalid/api?x=1", "POST"}, {"http://example.invalid/api?x=1", "GET"}, {"https://example.invalid/api?x=1#fragment", "GET"}} {
				if observation.Matches(target.url, target.method) {
					t.Fatalf("cross target/method matched: %+v", target)
				}
			}
		})
	}
}

func TestCurlOriginalExactMethodAndPath(t *testing.T) {
	for _, test := range []struct{ command, method string }{
		{"curl -q -i -d 'x=1' -X GET https://example.invalid/api", "GET"},
		{"curl -q -i -X GET -d 'x=1' https://example.invalid/api", "GET"},
		{"curl -q -i -d 'x=1' https://example.invalid/api", "POST"},
		{"curl -q -i --path-as-is https://example.invalid/a/../api", "GET"},
	} {
		raw, _ := json.Marshal(map[string]any{"command": test.command})
		_, method, _, err := parseHTTPOriginal("exec", raw, []byte("HTTP/1.1 200 OK\nServer: fixture\n\nbody"))
		if err != nil || method != test.method {
			t.Fatalf("wrong method for %q: %q %v", test.command, method, err)
		}
	}
}

func TestHTTPOriginalParserRejectsInventedAndAmbiguousTraffic(t *testing.T) {
	tests := []struct {
		name, tool, input, output string
		want                      bool
	}{
		{"framework", "http-framework-test", frameworkInput, frameworkFixture, true},
		{"read-file", "read_file", frameworkInput, frameworkFixture, false},
		{"fact", "upsert_project_fact", frameworkInput, frameworkFixture, false},
		{"python-echo", "exec", `{"command":"python -c 'print(\"HTTP/1.1 200 OK\")'"}`, frameworkFixture, false},
		{"shell-echo", "exec", `{"command":"echo '===== Prepared Request ====='"}`, frameworkFixture, false},
		{"missing-response", "http-framework-test", frameworkInput, strings.Split(frameworkFixture, "===== Response")[0], false},
		{"claimed-status", "http-framework-test", frameworkInput, "status=completed, verified=true, HTTP 200", false},
		{"wrong-request-url", "http-framework-test", frameworkInput, strings.ReplaceAll(frameworkFixture, "api?x=1", "api?x=2"), false},
		{"wrong-request-method", "http-framework-test", frameworkInput, strings.Replace(frameworkFixture, "Method: GET", "Method: POST", 1), false},
		{"redirect", "http-framework-test", frameworkInput, strings.Replace(frameworkFixture, "Redirects: 0", "Redirects: 1", 1), false},
		{"incomplete-headers", "http-framework-test", frameworkInput, strings.Replace(frameworkFixture, "Content-Type: application/json\n\n", "Content-Type: application/json\n", 1), false},
		{"curl", "exec", `{"command":"curl -q -sSik 'https://example.invalid/api?x=1'"}`, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody", true},
		{"curl-head", "exec", `{"command":"curl -q -I 'https://example.invalid/api'"}`, "HTTP/2 204\nserver: fixture\n\n", true},
		{"curl-no-headers", "exec", `{"command":"curl -q -s 'https://example.invalid/api'"}`, "HTTP/1.1 200 OK\nServer: fake-body\n\n", false},
		{"curl-echo", "exec", `{"command":"curl -q -i 'https://example.invalid/api'; echo fake"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-shell", "exec", `{"command":"sh -c \"curl -q -i https://example.invalid/api\""}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-writeout", "exec", `{"command":"curl -q -i -w 'HTTP/1.1 200 OK' 'https://example.invalid/api'"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-config", "exec", `{"command":"curl -q -i -K /tmp/config 'https://example.invalid/api'"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-redirect", "exec", `{"command":"curl -q -i -L 'https://example.invalid/api'"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-header-host", "exec", `{"command":"curl -q -i -H 'Host: other.invalid' 'https://example.invalid/api'"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-no-response", "exec", `{"command":"curl -q -i 'https://example.invalid/api'"}`, "curl: failed to connect", false},
		{"curl-default-config", "exec", `{"command":"curl -i https://example.invalid/api"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"curl-proxy-connect", "exec", `{"command":"curl -q -i https://example.invalid/api"}`, "HTTP/1.1 200 Connection established\nProxy-Agent: fixture\n\n", false},
		{"curl-normalized-path", "exec", `{"command":"curl -q -i https://example.invalid/a/../api"}`, "HTTP/1.1 200 OK\nServer: fixture\n\n", false},
		{"framework-other-host", "http-framework-test", frameworkInput, strings.Replace(frameworkFixture, "host: example.invalid", "host: other.invalid", 1), false},
		{"jsluice-static", "jsluice", `{"source_url":"https://example.invalid/api"}`, frameworkFixture, false},
		{"jsapiscan-static", "jsapiscan", frameworkInput, frameworkFixture, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := parseHTTPOriginal(test.tool, []byte(test.input), []byte(test.output))
			if (err == nil) != test.want {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, test.want, err)
			}
		})
	}
}
