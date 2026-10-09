package security

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/mcp"

	"github.com/cloudwego/eino/adk/filesystem"
	"go.uber.org/zap"
)

// Use a local test process, not Python, curl or a network endpoint, to verify
// pre-dispatch admission on every supported development OS.
func TestRepeatGuardProcessHelper(t *testing.T) {
	if os.Getenv("REPEAT_GUARD_PROCESS_HELPER") != "1" {
		return
	}
	path := os.Getenv("REPEAT_GUARD_PROCESS_MARKER")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	_, _ = file.WriteString("executed\n")
	_ = file.Close()
	if os.Getenv("REPEAT_GUARD_PROCESS_TTY") == "1" {
		fmt.Fprintln(os.Stderr, "not a tty")
		os.Exit(1)
	}
	fmt.Printf("HTTP/2 200 OK\nContent-Type: application/json\n\n{\"pid\":%d}\n", os.Getpid())
	os.Exit(0)
}

func TestHTTPRepeatFrameworkExecutorAndAsyncServer(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "executions")
	t.Setenv("REPEAT_GUARD_PROCESS_HELPER", "1")
	t.Setenv("REPEAT_GUARD_PROCESS_MARKER", marker)
	server := mcp.NewServer(zap.NewNop())
	cfg := &config.SecurityConfig{Tools: []config.ToolConfig{{
		Name: "http-framework-test", Command: program,
		Args: []string{"-test.run=^TestRepeatGuardProcessHelper$", "--"}, Enabled: true,
		Parameters: []config.ParameterConfig{{Name: "url", Type: "string", Required: true, Flag: "--url"}},
	}}}
	executor := NewExecutor(cfg, server, zap.NewNop())
	executor.SetToolOutputSpillRoot(t.TempDir())
	executor.RegisterTools(server)
	ctx := repeatGuardContext(t.Name())
	args := map[string]interface{}{"url": "https://example.test/probe?id=1"}
	for i := 0; i < httpRepeatLimit; i++ {
		result, id, err := server.CallTool(ctx, "http-framework-test", args)
		if err != nil || result == nil || result.IsError || id == "" {
			t.Fatalf("call %d: result=%+v id=%s error=%v", i+1, result, id, err)
		}
	}
	result, _, err := server.CallTool(ctx, "http-framework-test", args)
	if err != nil || result == nil || !result.IsError || !strings.Contains(mcp.ToolResultPlainText(result), "5/5") {
		t.Fatalf("sixth call did not return admission denial: %+v %v", result, err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || strings.Count(string(data), "executed\n") != httpRepeatLimit {
		t.Fatalf("expected exactly five real dispatches: %q %v", data, err)
	}
	// The direct executor must share the same counter; the MCP queue must not
	// increment it a second time, or the first five assertions above would fail.
	result, err = executor.ExecuteTool(ctx, "http-framework-test", args)
	if err != nil || result == nil || !result.IsError || !strings.Contains(mcp.ToolResultPlainText(result), "5/5") {
		t.Fatalf("direct executor bypassed shared counter: %+v %v", result, err)
	}
	result, err = executor.ExecuteTool(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/probe?id=2"})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("different query was blocked: %+v %v", result, err)
	}
	t.Setenv("REPEAT_GUARD_PROCESS_TTY", "1")
	result, err = executor.ExecuteTool(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/tty"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("expected fixture process failure: %+v %v", result, err)
	}
	data, err = os.ReadFile(marker)
	if err != nil || strings.Count(string(data), "executed\n") != httpRepeatLimit+2 {
		t.Fatalf("TTY text caused an uncounted retry: %q %v", data, err)
	}
}

func TestHTTPRepeatExecAndExecuteShareAdmission(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	command := "curl -q -sSi https://example.test/a"
	for i := 0; i < httpRepeatLimit; i++ {
		takeRepeatSlot(t, ctx, "exec", map[string]interface{}{"command": command})
	}
	executor := NewExecutor(&config.SecurityConfig{}, nil, zap.NewNop())
	result, err := executor.ExecuteTool(ctx, "exec", map[string]interface{}{"command": command, "shell": "missing-shell-must-not-start"})
	if err != nil || result == nil || !strings.Contains(mcp.ToolResultPlainText(result), "5/5") {
		t.Fatalf("exec failed to block before starting shell: %+v %v", result, err)
	}
	for _, background := range []bool{false, true} {
		sr, err := NewEinoStreamingShell().ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: "export PYTHONUNBUFFERED=1\n" + command, RunInBackendGround: background})
		if err != nil {
			t.Fatal(err)
		}
		_, err = sr.Recv()
		sr.Close()
		if err == nil || !strings.Contains(err.Error(), "5/5") {
			t.Fatalf("execute background=%v did not enforce pre-start quota: %v", background, err)
		}
	}
	if rec := globalCommandRepeatRegistry.sessions[t.Name()]; len(rec.entries) != 0 {
		t.Fatal("rejections were incorrectly recorded as actual command results")
	}
}

func TestCommandRepeatExecuteRecordsActualOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native execute uses /bin/sh; its pre-start admission is tested separately on Windows")
	}
	resetCommandRepeatRegistryForTest(t)
	ctx := repeatGuardContext(t.Name())
	for i := 0; i <= commandRepeatLimit; i++ {
		sr, err := NewEinoStreamingShell().ExecuteStreaming(ctx, &filesystem.ExecuteRequest{Command: "printf stable-result"})
		if err != nil {
			t.Fatal(err)
		}
		var runErr error
		for {
			_, runErr = sr.Recv()
			if runErr != nil {
				break
			}
		}
		sr.Close()
		if i < commandRepeatLimit && !errors.Is(runErr, io.EOF) {
			t.Fatalf("call %d: %v", i+1, runErr)
		}
		if i == commandRepeatLimit && (runErr == nil || !strings.Contains(runErr.Error(), "结果稳定")) {
			t.Fatalf("execute stable output was not recorded: %v", runErr)
		}
	}
}

func TestHTTPRepeatCancelledAdmissionDoesNotConsume(t *testing.T) {
	resetCommandRepeatRegistryForTest(t)
	ctx, cancel := context.WithCancel(repeatGuardContext(t.Name()))
	cancel()
	if _, err := AcquireHTTPRepeatGuard(ctx, "http-framework-test", map[string]interface{}{"url": "https://example.test/a"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled admission: %v", err)
	}
	if len(globalCommandRepeatRegistry.sessions) != 0 {
		t.Fatal("cancelled work consumed a counter")
	}
}
