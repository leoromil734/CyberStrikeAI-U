package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func jsPipelineFixture(t *testing.T, tool string) (*resultPipeline, context.Context, evidence.Execution, string) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "fixture.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	p := &resultPipeline{db: db, root: filepath.Join(t.TempDir(), "reduction"), logger: zap.NewNop()}
	e := evidence.Execution{ID: uuid.NewString(), Access: evidence.Access{ProjectID: "p", ConversationID: "c", Owner: "u"}, Tool: tool, Status: "completed", Completion: evidence.Complete, FinishedAt: time.Now()}
	ctx := evidence.WithAccess(context.Background(), e.Access)
	if err = db.RecordExecution(ctx, e); err != nil {
		t.Fatal(err)
	}
	reduction, err := evidence.ReductionRoot(p.root, e)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(reduction.Path), "executions", e.ID)
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return p, ctx, e, dir
}

func writeJSFixture(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func completeJSLuiceFixture(t *testing.T, dir string, e evidence.Execution) string {
	t.Helper()
	job := filepath.Join(dir, "jsluice", "execution-"+e.ID)
	source := "fetch('/api/EXPR', {method:'POST'});"
	hash := sha256.Sum256([]byte(source))
	files := map[string]string{"source.js": source, "stderr.log": "", "raw.jsonl": "{\"url\":\"/api/EXPR\",\"method\":\"POST\"}\n", "urls.jsonl": `{"schema":"csai.jsluice.v1","mode":"urls","source_js":"https://example.test/app.js","source_sha256":"` + hex.EncodeToString(hash[:]) + `","url":"/api/EXPR","method":"POST","relativeURL":"/api/EXPR"}` + "\n"}
	meta := map[string]interface{}{}
	for name, data := range files {
		writeJSFixture(t, filepath.Join(job, name), data)
		sum := sha256.Sum256([]byte(data))
		meta[name] = map[string]interface{}{"sha256": hex.EncodeToString(sum[:]), "bytes": len(data)}
	}
	manifest, _ := json.Marshal(map[string]interface{}{"schema": "csai.jsluice.v1", "tool": "jsluice", "execution_id": e.ID, "mode": "urls", "source_sha256": hex.EncodeToString(hash[:]), "complete": true, "analysis_complete": true, "export_complete": true, "raw_complete": true, "coverage_complete": false, "files": meta})
	writeJSFixture(t, filepath.Join(job, "manifest.json"), string(manifest))
	return job
}

func TestJSLuiceWorkspacePipelineKeepsStaticCandidatesAndOriginals(t *testing.T) {
	p, ctx, e, dir := jsPipelineFixture(t, "jsluice")
	job := completeJSLuiceFixture(t, dir, e)
	original := &mcp.ToolExecution{ID: e.ID, ToolName: e.Tool, Arguments: map[string]interface{}{"mode": "urls"}, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: `{"complete":true,"work_dir":"/untrusted/path"}`}}}}
	state, reason, err := p.process(ctx, e, original)
	if err != nil || state != "complete" {
		t.Fatalf("%s %s %v", state, reason, err)
	}
	records, err := p.db.ReconInventory(ctx, e.ID, "endpoint", 100, 0)
	if err != nil || len(records) != 1 || records[0].RawURL != "/api/EXPR" || records[0].Method != "POST" || !records[0].CandidateOnly {
		t.Fatalf("%+v %v", records, err)
	}
	counts, err := p.db.ReconInventoryCounts(ctx, e.ID)
	if err != nil || counts.Hosts != 0 || counts.Services != 0 || counts.Candidates != 0 {
		t.Fatalf("invented observed assets: %+v %v", counts, err)
	}
	artifacts, err := p.db.ResultArtifacts(ctx, e.ID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "source.js", "raw.jsonl", "urls.jsonl", "stderr.log"} {
		found := false
		for _, a := range artifacts {
			if filepath.Base(a.Path) == name {
				found = true
				if len(a.SHA256) != 64 {
					t.Fatal("missing hash")
				}
			}
		}
		if !found {
			t.Errorf("missing original %s", name)
		}
	}
	writeJSFixture(t, filepath.Join(job, "source.js"), "changed source")
	state, _, err = p.process(ctx, e, original)
	if err == nil || state != "failed" {
		t.Fatal("source hash mutation accepted")
	}
}

func TestJSLuiceMissingSourceMetadataCannotImportNormalizedRows(t *testing.T) {
	p, ctx, e, dir := jsPipelineFixture(t, "jsluice")
	job := completeJSLuiceFixture(t, dir, e)
	path := filepath.Join(job, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]interface{}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	delete(manifest["files"].(map[string]interface{}), "source.js")
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeJSFixture(t, path, string(data))
	original := &mcp.ToolExecution{ID: e.ID, ToolName: e.Tool}
	state, reason, err := p.process(ctx, e, original)
	if err != nil || state != "partial" {
		t.Fatalf("%s %s %v", state, reason, err)
	}
	counts, err := p.db.ReconInventoryCounts(ctx, e.ID)
	if err != nil || counts.Total() != 0 {
		t.Fatalf("normalized rows without verified source were imported: %+v %v", counts, err)
	}
}

func TestLegacyJSWorkspaceCSVIsIngestedWithoutTrustingStdout(t *testing.T) {
	p, ctx, e, dir := jsPipelineFixture(t, "jsapiscan")
	job := filepath.Join(dir, "jsapiscan", "execution-"+e.ID)
	writeJSFixture(t, filepath.Join(job, "manifest.json"), `{"complete":true,"scan_complete":true,"export_complete":true,"raw_complete":true}`)
	writeJSFixture(t, filepath.Join(job, "work", "batch-0001", "result.csv"), "URL,Method,Status\nhttps://example.test/api?route=one,POST,200\n")
	original := &mcp.ToolExecution{ID: e.ID, ToolName: e.Tool, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: `{"manifest_file":"/fake/manifest.json","work_dir":"/fake/work"}`}}}}
	state, reason, err := p.process(ctx, e, original)
	if err != nil || state != "complete" {
		t.Fatalf("workspace CSV unavailable: %s %s %v", state, reason, err)
	}
	records, err := p.db.ReconInventory(ctx, e.ID, "endpoint", 100, 0)
	if err != nil || len(records) != 1 || !strings.Contains(records[0].RawURL, "route=one") {
		t.Fatalf("%+v %v", records, err)
	}
}

func TestJSMissingWorkspaceDoesNotAcceptStdoutPath(t *testing.T) {
	p, ctx, e, _ := jsPipelineFixture(t, "jsapiscan")
	untrusted := t.TempDir()
	writeJSFixture(t, filepath.Join(untrusted, "result.csv"), "URL,Method\nhttps://example.test/forged,GET\n")
	body, _ := json.Marshal(map[string]string{"work_dir": untrusted, "manifest_file": filepath.Join(untrusted, "manifest.json")})
	original := &mcp.ToolExecution{ID: e.ID, ToolName: e.Tool, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(body)}}}}
	state, _, err := p.process(ctx, e, original)
	if err != nil || state != "partial" {
		t.Fatalf("%s %v", state, err)
	}
	counts, err := p.db.ReconInventoryCounts(ctx, e.ID)
	if err != nil || counts.Total() != 0 {
		t.Fatal("untrusted stdout path became inventory")
	}
}

func TestIndependentMachineOriginalPreferredOverMixedLogs(t *testing.T) {
	for _, test := range []struct{ tool, name, body string }{
		{"nmap", "nmap.xml", `<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>`},
		{"nuclei", "nuclei.jsonl", `{"template-id":"fixture","matched-at":"https://example.test/a","info":{"severity":"info"}}` + "\n"},
	} {
		t.Run(test.tool, func(t *testing.T) {
			p, ctx, e, dir := jsPipelineFixture(t, test.tool)
			writeJSFixture(t, filepath.Join(dir, test.name), test.body)
			original := &mcp.ToolExecution{ID: e.ID, ToolName: e.Tool, Result: &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "human log mixed with stderr; not machine input"}}}}
			state, reason, err := p.process(ctx, e, original)
			if err != nil || state != "complete" {
				t.Fatalf("%s %s %v", state, reason, err)
			}
			sources, err := p.db.ReconSources(ctx, e.ID, 100, 0, time.Now())
			if err != nil || len(sources) != 1 || sources[0].State != evidence.Parsed {
				t.Fatalf("logs parsed as data: %+v %v", sources, err)
			}
		})
	}
}
