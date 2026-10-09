package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/recon"
	"cyberstrike-ai/internal/security"

	"go.uber.org/zap"
)

const pipelineNmapOriginal = `<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`
const pipelineNucleiOriginal = "{\"template-id\":\"local-fixture\",\"matched-at\":\"https://example.invalid/a?id=7\",\"info\":{\"severity\":\"info\"}}\n"

func TestMachinePipelineHelperProcess(t *testing.T) {
	if os.Getenv("CSAI_PIPELINE_HELPER") != "1" {
		return
	}
	argv := os.Args
	for len(argv) > 0 && argv[0] != "--" {
		argv = argv[1:]
	}
	if len(argv) < 2 {
		os.Exit(2)
	}
	tool, argv := argv[1], argv[2:]
	format := recon.NativeStdoutFormat(tool, argv)
	fmt.Fprintln(os.Stderr, "WARNING: sonic runtime diagnostic; not machine stdout")
	switch {
	case tool == "nmap" && format == "xml":
		fmt.Fprint(os.Stdout, pipelineNmapOriginal)
	case tool == "nuclei" && format == "jsonl":
		fmt.Fprint(os.Stdout, pipelineNucleiOriginal)
	default:
		os.Exit(3) // The real default flags must reach the process.
	}
	os.Exit(0)
}

func TestNamedMachineOriginalExecutionToInventoryAndReplay(t *testing.T) {
	t.Setenv("CSAI_PIPELINE_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"nmap", "nuclei"} {
		t.Run(tool, func(t *testing.T) {
			db, err := database.NewDB(filepath.Join(t.TempDir(), "machine.db"), zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			user, err := db.CreateRBACUser("machine-user", "Machine User", "hash", true, nil)
			if err != nil {
				t.Fatal(err)
			}
			project, err := db.CreateProject(&database.Project{Name: "machine fixture"})
			if err != nil {
				t.Fatal(err)
			}
			conv, err := db.CreateConversation("machine fixture", database.ConversationCreateMeta{})
			if err != nil {
				t.Fatal(err)
			}
			if err = db.SetConversationProjectID(conv.ID, project.ID); err != nil {
				t.Fatal(err)
			}
			if _, err = db.BeginAssessmentRun(conv.ID, project.ID, "", "", database.AssessmentModeComprehensive, "machine-run"); err != nil {
				t.Fatal(err)
			}
			ctx := authctx.WithPrincipal(context.Background(), authctx.NewPrincipal(user.ID, user.Username, database.RBACScopeAll, map[string]bool{"monitor:read": true}))
			ctx = mcp.WithMCPConversationID(ctx, conv.ID)
			ctx = mcp.WithMCPProjectID(ctx, project.ID)
			p := &resultPipeline{db: db, root: filepath.Join(t.TempDir(), "reduction"), logger: zap.NewNop(), wake: make(chan struct{}, 1)}
			cfg, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", tool+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Command = binary
			cfg.Args = append([]string{"-test.run=^TestMachinePipelineHelperProcess$", "--", tool}, cfg.Args...)
			securityConfig := &config.SecurityConfig{Tools: []config.ToolConfig{*cfg}}
			server := mcp.NewServerWithStorage(zap.NewNop(), db)
			server.ConfigureToolResultSpillRoot(p.root)
			server.SetToolAuthorizer(func(context.Context, string, map[string]interface{}) error { return nil })
			server.SetExecutionObserver(p.observe)
			executor := security.NewExecutor(securityConfig, server, zap.NewNop())
			executor.SetToolOutputSpillRoot(p.root)
			executor.RegisterTools(server)
			args := map[string]interface{}{"target": "example.invalid"} // Omit output defaults deliberately.
			result, id, err := server.CallTool(ctx, tool, args)
			if err != nil || result == nil || result.IsError || !strings.Contains(mcp.ToolResultPlainText(result), "sonic runtime diagnostic") {
				t.Fatalf("local process did not complete with diagnostics: %+v %v", result, err)
			}
			if len(args) != 1 {
				t.Fatal("caller's map was changed")
			}
			// Simulate a configuration reload BEFORE the ingestion worker runs.
			for i := range securityConfig.Tools[0].Parameters {
				param := &securityConfig.Tools[0].Parameters[i]
				if param.Name == "xml_output" {
					param.Default = ""
				}
				if param.Name == "json_output" {
					param.Default = false
				}
			}
			claim, err := db.ClaimResultIngestion(ctx, id, resultIngestionLease)
			if err != nil || claim == nil {
				t.Fatalf("trusted observer did not queue original: %+v %v", claim, err)
			}
			snapshot, err := db.LoadResultIngestionSnapshot(ctx, *claim)
			if err != nil || snapshot.Original.Invocation == nil {
				t.Fatalf("durable invocation missing: %+v %v", snapshot, err)
			}
			if tool == "nmap" && snapshot.Original.Arguments["xml_output"] != "-" || tool == "nuclei" && snapshot.Original.Arguments["json_output"] != true {
				t.Fatalf("saved defaults were inferred from new config: %+v", snapshot.Original.Arguments)
			}
			if err = p.runClaim(ctx, *claim); err != nil {
				t.Fatal(err)
			}
			job, err := db.ResultIngestionJob(ctx, id)
			if err != nil || job.State != "complete" {
				t.Fatalf("original not fully ingested: %+v %v", job, err)
			}
			access := evidence.WithAccess(ctx, evidence.Access{ProjectID: project.ID, ConversationID: conv.ID, Owner: user.ID})
			sources, err := db.ReconSources(access, id, 100, 0, time.Now())
			if err != nil || len(sources) != 1 || sources[0].Tool != tool || sources[0].State != evidence.Parsed || sources[0].Stats.Rejected != 0 {
				t.Fatalf("stderr leaked into machine source: %+v %v", sources, err)
			}
			body := pipelineNmapOriginal
			kind := recon.Service
			if tool == "nuclei" {
				body, kind = pipelineNucleiOriginal, recon.Candidate
			}
			hash := sha256.Sum256([]byte(body))
			if sources[0].SHA256 != hex.EncodeToString(hash[:]) {
				t.Fatal("source hash is not actual stdout hash")
			}
			records, err := db.ReconInventory(access, id, kind, 100, 0)
			if err != nil || len(records) != 1 || !records[0].CandidateOnly || records[0].ScopeState != recon.UnknownScope || records[0].Location.Length <= 0 {
				t.Fatalf("original provenance or candidate boundary lost: %+v %v", records, err)
			}
			artifacts, err := db.ResultArtifacts(access, id, 100, 0)
			if err != nil || len(artifacts) != 3 {
				t.Fatalf("input, display log and machine original not all registered: %+v %v", artifacts, err)
			}
			for _, artifact := range artifacts {
				if artifact.Kind == "output" && artifact.Format != snapshot.Original.Invocation.StdoutFormat {
					t.Fatalf("display log is being parsed: %+v", artifact)
				}
			}
			// Replay uses the frozen invocation, never the current YAML or display.
			if err = db.SetResultIngestionState(access, snapshot.Execution, "failed", "fixture replay"); err != nil {
				t.Fatal(err)
			}
			if err = db.RequeueResultIngestion(access, snapshot.Execution); err != nil {
				t.Fatal(err)
			}
			replayClaim, err := db.ClaimResultIngestion(ctx, id, resultIngestionLease)
			if err != nil || replayClaim == nil {
				t.Fatalf("replay claim: %+v %v", replayClaim, err)
			}
			if err = p.runClaim(ctx, *replayClaim); err != nil {
				t.Fatal(err)
			}
			sources, err = db.ReconSources(access, id, 100, 0, time.Now())
			if err != nil || len(sources) != 1 || sources[0].SHA256 != hex.EncodeToString(hash[:]) {
				t.Fatalf("replay drifted: %+v %v", sources, err)
			}
			var findings int
			if err = db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities`).Scan(&findings); err != nil || findings != 0 {
				t.Fatal("offline scanner candidate became a vulnerability")
			}
		})
	}
}

func TestDeclaredTextDoesNotAdoptMachineNamedFile(t *testing.T) {
	for _, tool := range []string{"nmap", "nuclei"} {
		p, ctx, e, dir := jsPipelineFixture(t, tool)
		name, body := "nmap.xml", pipelineNmapOriginal
		if tool == "nuclei" {
			name, body = "nuclei.jsonl", pipelineNucleiOriginal
		}
		writeJSFixture(t, filepath.Join(dir, name), body)
		original := &mcp.ToolExecution{ToolName: tool, Invocation: &mcp.ToolInvocation{Version: mcp.NativeCLIInvocationVersion, ToolName: tool, StdoutFormat: "text"}, Arguments: map[string]interface{}{"target": "fixture"}, Result: textResult("human scanner output", false)}
		state, _, err := p.process(ctx, e, original)
		if err != nil || state != "partial" {
			t.Fatalf("text contract incorrectly became machine success: %s %v", state, err)
		}
		artifacts, err := p.db.ResultArtifacts(ctx, e.ID, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, artifact := range artifacts {
			if filepath.Base(artifact.Path) == name {
				t.Fatal("undeclared file auto-adopted")
			}
		}
	}
}

func TestMachineCaptureFailureRemainsPartial(t *testing.T) {
	p, ctx, e, dir := jsPipelineFixture(t, "nuclei")
	writeJSFixture(t, filepath.Join(dir, "nuclei.jsonl"), pipelineNucleiOriginal)
	original := &mcp.ToolExecution{ToolName: e.Tool, Invocation: &mcp.ToolInvocation{Version: mcp.NativeCLIInvocationVersion, ToolName: e.Tool, StdoutFormat: "jsonl", MachineFile: "nuclei.jsonl", CaptureError: "machine_original_byte_limit"}, Arguments: map[string]interface{}{"json_output": true}, Result: textResult("display log", false)}
	state, _, err := p.process(ctx, e, original)
	if err != nil || state != "partial" {
		t.Fatalf("truncated machine capture claimed complete: %s %v", state, err)
	}
	sources, err := p.db.ReconSources(ctx, e.ID, 100, 0, time.Now())
	if err != nil || len(sources) != 1 || sources[0].Completion != evidence.Partial {
		t.Fatalf("capture failure lost: %+v %v", sources, err)
	}
}

func TestHistoricalUndeclaredMachineOutputStaysUnsupported(t *testing.T) {
	for _, tool := range []string{"nmap", "nuclei"} {
		p, ctx, e, _ := jsPipelineFixture(t, tool)
		body := pipelineNmapOriginal
		if tool == "nuclei" {
			body = pipelineNucleiOriginal
		}
		original := &mcp.ToolExecution{ToolName: tool, Arguments: map[string]interface{}{"target": "fixture", "invocation": map[string]interface{}{"stdout_format": "xml"}}, Result: textResult(body, false)}
		state, _, err := p.process(ctx, e, original)
		if err != nil || state != "partial" {
			t.Fatalf("historical format was guessed: %s %v", state, err)
		}
		sources, err := p.db.ReconSources(ctx, e.ID, 100, 0, time.Now())
		if err != nil || len(sources) != 1 || sources[0].State != evidence.Unsupported {
			t.Fatalf("historical/forged contract promoted: %+v %v", sources, err)
		}
	}
}
