package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"

	"go.uber.org/zap"
)

const machineNmapFixture = `<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>`
const machineNucleiFixture = "{\"template-id\":\"fixture\",\"matched-at\":\"https://example.invalid/path\"}\n"

// A child copy of this test binary is the scanner. It validates actual CLI
// flags, writes only local files and emits diagnostics on stderr; no network.
func TestMachineOriginalHelperProcess(t *testing.T) {
	if os.Getenv("CSAI_MACHINE_HELPER") != "1" {
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
	invocation := nativeInvocation(tool, argv)
	fmt.Fprintln(os.Stderr, "WARNING: sonic diagnostic; not scanner data")
	switch tool {
	case "nmap":
		if invocation.StdoutFormat == "xml" {
			fmt.Fprint(os.Stdout, machineNmapFixture)
		} else {
			fmt.Fprint(os.Stdout, "Nmap human scan summary\n")
			for i, arg := range argv {
				if arg == "-oX" && i+1 < len(argv) && argv[i+1] != "-" {
					if err := os.WriteFile(argv[i+1], []byte(machineNmapFixture), 0600); err != nil {
						os.Exit(3)
					}
				}
			}
		}
	case "nuclei":
		if invocation.StdoutFormat == "jsonl" {
			if os.Getenv("CSAI_MACHINE_EMPTY") != "1" {
				fmt.Fprint(os.Stdout, machineNucleiFixture)
			}
		} else {
			fmt.Fprint(os.Stdout, "[fixture] [http] https://example.invalid\n")
		}
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func TestNamedScannerEffectiveDefaultsAndMachineOriginal(t *testing.T) {
	t.Setenv("CSAI_MACHINE_HELPER", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, tool, format, machine string
		args                        map[string]interface{}
		empty                       bool
	}{
		{"nmap omitted", "nmap", "xml", "nmap.xml", nil, false},
		{"nmap explicit empty", "nmap", "text", "", map[string]interface{}{"xml_output": ""}, false},
		{"nmap file", "nmap", "text", "", map[string]interface{}{"xml_output": filepath.Join(t.TempDir(), "user chosen.xml")}, false},
		{"nmap mixed", "nmap", "text", "", map[string]interface{}{"additional_args": "-oN -"}, false},
		{"nmap duplicate", "nmap", "text", "", map[string]interface{}{"additional_args": "-oX -"}, false},
		{"nuclei omitted", "nuclei", "jsonl", "nuclei.jsonl", nil, false},
		{"nuclei disabled", "nuclei", "text", "", map[string]interface{}{"json_output": false}, false},
		{"nuclei overridden", "nuclei", "text", "", map[string]interface{}{"additional_args": "-jsonl=false"}, false},
		{"nuclei export only", "nuclei", "text", "", map[string]interface{}{"json_output": false, "additional_args": "-jsonl-export fixture.jsonl"}, false},
		{"nuclei no matches", "nuclei", "jsonl", "nuclei.jsonl", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.empty {
				t.Setenv("CSAI_MACHINE_EMPTY", "1")
			}
			cfg, err := config.LoadToolFromFile(filepath.Join("..", "..", "tools", test.tool+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Command = binary
			cfg.Args = append([]string{"-test.run=^TestMachineOriginalHelperProcess$", "--", test.tool}, cfg.Args...)
			server := mcp.NewServer(zap.NewNop())
			executor := NewExecutor(&config.SecurityConfig{Tools: []config.ToolConfig{*cfg}}, server, zap.NewNop())
			root := filepath.Join(t.TempDir(), "reduction")
			executor.SetToolOutputSpillRoot(root)
			executor.SetToolOutputMaxBytes(1024)
			server.ConfigureToolResultSpillRoot(root)
			executor.RegisterTools(server)
			var original *mcp.ToolExecution
			server.SetExecutionObserver(func(_ context.Context, e *mcp.ToolExecution) {
				if e.EndTime != nil {
					original = e
				}
			})
			args := map[string]interface{}{"target": "example.invalid", "invocation": map[string]interface{}{"stdout_format": "xml", "machine_file": "forged"}}
			for key, value := range test.args {
				args[key] = value
			}
			before := make(map[string]interface{}, len(args))
			for key, value := range args {
				before[key] = value
			}
			ctx := mcp.WithMCPConversationID(context.Background(), "fixture-conversation")
			result, id, err := server.CallTool(ctx, test.tool, args)
			if err != nil || result == nil || result.IsError || original == nil || original.Invocation == nil {
				t.Fatalf("real execution: %v %+v %+v", err, result, original)
			}
			if !reflect.DeepEqual(args, before) {
				t.Fatal("executor mutated caller-owned arguments")
			}
			if original.Invocation.StdoutFormat != test.format || original.Invocation.MachineFile != test.machine {
				t.Fatalf("wrong effective output contract: %+v", original.Invocation)
			}
			if !strings.Contains(mcp.ToolResultPlainText(result), "sonic diagnostic") {
				t.Fatal("diagnostics lost from display log")
			}
			if test.tool == "nmap" {
				want := interface{}("-")
				if value, exists := test.args["xml_output"]; exists {
					want = value
				}
				if original.Arguments["xml_output"] != want {
					t.Fatalf("default/explicit value lost: %+v", original.Arguments)
				}
			} else if original.Arguments["json_output"] != (test.args["json_output"] != false) {
				t.Fatalf("nuclei effective boolean lost: %+v", original.Arguments)
			}
			reduction, err := evidence.ReductionRoot(root, evidence.Execution{ID: id, Access: evidence.Access{ConversationID: "fixture-conversation"}})
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(filepath.Dir(reduction.Path), "executions", id)
			for _, name := range []string{"nmap.xml", "nuclei.jsonl"} {
				body, readErr := os.ReadFile(filepath.Join(dir, name))
				if name != test.machine {
					if !os.IsNotExist(readErr) {
						t.Fatalf("undeclared machine original %s: %v", name, readErr)
					}
					continue
				}
				want := machineNmapFixture
				if test.tool == "nuclei" {
					want = machineNucleiFixture
				}
				if test.empty {
					want = ""
				}
				if readErr != nil || string(body) != want {
					t.Fatalf("stdout is not exact machine original: %q %v", body, readErr)
				}
			}
			if path, ok := test.args["xml_output"].(string); ok && path != "" {
				body, err := os.ReadFile(path)
				if err != nil || string(body) != machineNmapFixture {
					t.Fatalf("user output path was changed: %q %v", body, err)
				}
			}
		})
	}
}

func TestMachineOriginalBoundedAndExclusive(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	capture := &machineOriginal{file: file, remaining: 3}
	if n, err := capture.Write([]byte("abcdef")); n != 6 || err != nil {
		t.Fatal("capture interrupted child drain")
	}
	if reason := capture.close(); reason != "machine_original_byte_limit" {
		t.Fatal(reason)
	}
	body, err := os.ReadFile(file.Name())
	if err != nil || string(body) != "abc" {
		t.Fatalf("bounded original: %q %v", body, err)
	}
	// A preexisting reserved filename must never be truncated or reused by
	// another capture, even if its content looks like the expected format.
	executor, _ := setupTestExecutor(t)
	executor.SetToolOutputSpillRoot(filepath.Join(t.TempDir(), "reduction"))
	ctx := mcp.WithMCPExecutionID(mcp.WithMCPConversationID(context.Background(), "fixture"), "10000000-0000-0000-0000-000000000001")
	first, err := executor.openMachineOriginal(ctx, nativeInvocation("nmap", []string{"-oX", "-"}))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = first.Write([]byte("immutable fixture"))
	first.close()
	if _, err = executor.openMachineOriginal(ctx, nativeInvocation("nmap", []string{"-oX", "-"})); !os.IsExist(err) {
		t.Fatalf("preexisting original replaced: %v", err)
	}
}
