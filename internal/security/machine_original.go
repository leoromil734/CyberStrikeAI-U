package security

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/recon"
)

// Snapshot defaults and aliases after building argv without changing command
// construction. Explicit false/empty values and the caller's map stay intact.
func (e *Executor) resolvedInvocationArgs(cfg *config.ToolConfig, args map[string]interface{}) map[string]interface{} {
	resolved := make(map[string]interface{}, len(args)+len(cfg.Parameters))
	for key, value := range args {
		resolved[key] = value
	}
	for _, param := range cfg.Parameters {
		// These fields are consumed directly by buildCommandArgs, not by
		// getParamValue; do not claim their unused defaults/aliases took effect.
		if param.Name == "scan_type" || param.Name == "additional_args" || (param.Name == "action" && param.Position == nil) {
			continue
		}
		if value := e.getParamValue(args, param); value != nil {
			resolved[param.Name] = value
		}
	}
	return resolved
}

func (e *Executor) recordInvocation(ctx context.Context, tool string, args map[string]interface{}, invocation *mcp.ToolInvocation) {
	if !mcp.RecordToolInvocation(ctx, tool, args, invocation) && e.mcpServer != nil {
		e.mcpServer.SetToolExecutionInvocation(mcp.MCPExecutionIDFromContext(ctx), tool, args, invocation)
	}
}

// This contract is derived from actual argv, after default/alias/file resolution,
// not from model-provided host-looking fields or a later version of the YAML.
func nativeInvocation(tool string, argv []string) *mcp.ToolInvocation {
	return &mcp.ToolInvocation{
		Version: mcp.NativeCLIInvocationVersion, ToolName: tool,
		Argv: append([]string(nil), argv...), StdoutFormat: recon.NativeStdoutFormat(tool, argv),
	}
}

// Only stdout with an explicit native machine contract is captured. File output
// choices are left untouched; we never read a caller-chosen arbitrary host path.
func (e *Executor) openMachineOriginal(ctx context.Context, invocation *mcp.ToolInvocation) (*machineOriginal, error) {
	name := ""
	switch recon.CanonicalTool(invocation.ToolName) {
	case "nmap":
		if invocation.StdoutFormat == "xml" {
			name = "nmap.xml"
		}
	case "nuclei":
		if invocation.StdoutFormat == "jsonl" {
			name = "nuclei.jsonl"
		}
	}
	if name == "" || mcp.MCPExecutionIDFromContext(ctx) == "" {
		return nil, nil
	}
	opts := e.spillOptsFromContext(ctx)
	root, err := evidence.ReductionRoot(opts.RootDir, evidence.Execution{ID: opts.ExecutionID, Access: evidence.Access{ProjectID: opts.ProjectID, ConversationID: opts.ConversationID}})
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(filepath.Dir(root.Path), "executions", opts.ExecutionID)
	if err = ensureArtifactDirectory(dir); err != nil {
		return nil, err
	}
	dirRoot, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer dirRoot.Close()
	file, err := dirRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	invocation.MachineFile = name
	return &machineOriginal{file: file, remaining: evidence.DefaultMaxArtifactBytes}, nil
}

// Retain exact bytes independently of bounded display output and diagnostics.
// A disk failure/limit never stops draining the child pipe; the saved contract
// marks the original partial instead of claiming the retained prefix complete.
type machineOriginal struct {
	mu        sync.Mutex
	file      *os.File
	remaining int64
	failure   string
	closed    bool
}

var _ io.Writer = (*machineOriginal)(nil)

func (m *machineOriginal) Write(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(data)
	if m.closed || m.failure != "" {
		return n, nil
	}
	if int64(len(data)) > m.remaining {
		data = data[:int(m.remaining)]
		m.failure = "machine_original_byte_limit"
	}
	written, err := m.file.Write(data)
	m.remaining -= int64(written)
	if err != nil || written != len(data) {
		m.failure = "machine_original_write_failed"
	}
	return n, nil
}

func (m *machineOriginal) close() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		if err := m.file.Close(); err != nil {
			m.failure = "machine_original_write_failed"
		}
		m.closed = true
	}
	return m.failure
}
