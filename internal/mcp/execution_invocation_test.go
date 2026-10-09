package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

func TestExecutionInvocationTrustedChannelAndPrivateCopies(t *testing.T) {
	service := NewExecutionService(nil, nil)
	args := map[string]interface{}{"target": "fixture", "invocation": map[string]interface{}{"stdout_format": "xml"}}
	invocation := &ToolInvocation{Version: NativeCLIInvocationVersion, ToolName: "nmap", Argv: []string{"-oX", "-", "fixture"}, StdoutFormat: "xml", MachineFile: "nmap.xml"}
	handle, err := service.Submit(context.Background(), ExecutionRequest{ToolName: "nmap", Arguments: args, Run: func(ctx context.Context) (*ToolResult, error) {
		if RecordToolInvocation(ctx, "nuclei", nil, invocation) {
			t.Error("wrong tool altered execution")
		}
		effective := cloneArgsMap(args)
		effective["xml_output"] = "-"
		if !RecordToolInvocation(ctx, "nmap", effective, invocation) {
			t.Error("trusted invocation not recorded")
		}
		effective["xml_output"] = "changed"
		effective["invocation"].(map[string]interface{})["stdout_format"] = "changed"
		invocation.Argv[0] = "changed"
		return &ToolResult{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Wait(context.Background(), handle.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := snapshot.Execution
	if got.Arguments["xml_output"] != "-" || got.Invocation.Argv[0] != "-oX" || got.Arguments["invocation"].(map[string]interface{})["stdout_format"] != "xml" {
		t.Fatalf("caller mutation changed metadata: %+v", got)
	}
	if _, exists := args["xml_output"]; exists {
		t.Fatal("caller arguments were changed")
	}
	// This is the same JSON round-trip used by durable ingestion snapshots.
	body, err := json.Marshal(got)
	var replay ToolExecution
	if err != nil || json.Unmarshal(body, &replay) != nil || replay.Invocation.MachineFile != "nmap.xml" {
		t.Fatalf("snapshot lost invocation: %s %v", body, err)
	}
	got.Invocation.Argv[0] = "snapshot mutation"
	got.Arguments["invocation"].(map[string]interface{})["stdout_format"] = "snapshot mutation"
	again, _ := service.Get(handle.ID)
	if again.Execution.Invocation.Argv[0] != "-oX" || again.Execution.Arguments["invocation"].(map[string]interface{})["stdout_format"] != "xml" {
		t.Fatal("snapshot exposed shared mutable metadata")
	}
}

func TestExecutionInvocationCannotComeFromModelArguments(t *testing.T) {
	service := NewExecutionService(nil, nil)
	h, err := service.Submit(context.Background(), ExecutionRequest{ToolName: "exec", Arguments: map[string]interface{}{
		"command": "echo fixture", "invocation": map[string]interface{}{"version": NativeCLIInvocationVersion, "tool_name": "nmap", "machine_file": "nmap.xml"},
	}, Run: func(context.Context) (*ToolResult, error) { return &ToolResult{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Wait(context.Background(), h.ID, 0)
	if err != nil || snapshot.Execution.Invocation != nil {
		t.Fatalf("untrusted metadata adopted: %+v %v", snapshot, err)
	}
}

func TestLegacyExecutionFinishKeepsTrustedInvocation(t *testing.T) {
	server := NewServer(zap.NewNop())
	args := map[string]interface{}{"target": "fixture"}
	id := server.BeginToolExecution(context.Background(), "nmap", args)
	invocation := &ToolInvocation{Version: NativeCLIInvocationVersion, ToolName: "nmap", Argv: []string{"-oX", "-"}, StdoutFormat: "xml"}
	if !server.SetToolExecutionInvocation(id, "nmap", map[string]interface{}{"target": "fixture", "xml_output": "-"}, invocation) {
		t.Fatal("legacy invocation not recorded")
	}
	var final *ToolExecution
	server.SetExecutionObserver(func(_ context.Context, e *ToolExecution) { final = e })
	server.FinishToolExecution(context.Background(), id, "nmap", args, "fixture", nil)
	if final == nil || final.Arguments["xml_output"] != "-" || final.Invocation == nil {
		t.Fatalf("Finish overwrote actual invocation: %+v", final)
	}
	if server.SetToolExecutionInvocation(id, "nmap", nil, invocation) {
		t.Fatal("terminal execution metadata was changed")
	}
}
