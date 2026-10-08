package pilab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxEventBytes = 96 * 1024

// ProcessRuntime uses an absolute script path and never invokes a shell. No
// inherited API keys, NODE_OPTIONS, user PI settings or MCP credentials are sent.
type ProcessRuntime struct{ Node, Script string }

func OptionsFromEnv() Options {
	root := os.Getenv("CYBERSTRIKE_PI_DATA_DIR")
	if root == "" {
		root = filepath.Join("data", "pi-lab")
	}
	script := os.Getenv("CYBERSTRIKE_PI_RUNNER")
	if script == "" {
		script = filepath.Join("runtimes", "pi-lab", "runner.mjs")
	}
	node := os.Getenv("CYBERSTRIKE_PI_NODE")
	if node == "" {
		node = "node"
	}
	if abs, err := filepath.Abs(script); err == nil {
		script = abs
	}
	return Options{Enabled: strings.EqualFold(os.Getenv("CYBERSTRIKE_PI_ENABLED"), "true"), Root: root, Runtime: &ProcessRuntime{Node: node, Script: script}}
}

func runtimeEnv() []string {
	var env []string
	for _, key := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "SystemDrive"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return append(env, "NO_COLOR=1", "PI_SKIP_VERSION_CHECK=1")
}

func (r *ProcessRuntime) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, r.Node, append([]string{r.Script}, args...)...)
	cmd.Env = runtimeEnv()
	cmd.WaitDelay = 2 * time.Second
	return cmd
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.limit - b.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func (r *ProcessRuntime) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := &cappedBuffer{limit: 4096}
	cmd := r.command(ctx, "--check")
	cmd.Dir = filepath.Dir(r.Script)
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return ErrUnavailable
	}
	var check struct {
		Ready   bool   `json:"ready"`
		Runtime string `json:"runtime"`
	}
	if err := json.Unmarshal(out.Bytes(), &check); err != nil || !check.Ready || check.Runtime != "pi-coding-agent" {
		return ErrUnavailable
	}
	return nil
}

func (r *ProcessRuntime) Run(ctx context.Context, workdir string, input Input, emit func(Event) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	payload, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("无法构建 PI 运行请求")
	}
	cmd := r.command(ctx)
	cmd.Dir = workdir
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	// stderr can contain provider response bodies/headers. Never publish or store it.
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("无法创建 PI 事件管道")
	}
	if err := cmd.Start(); err != nil {
		return ErrUnavailable
	}
	var streamErr error
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), maxEventBytes)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil || event.Type == "" {
			streamErr = fmt.Errorf("PI 运行时返回无效事件协议")
			cancel()
			break
		}
		if err := emit(event); err != nil {
			streamErr = err
			cancel()
			break
		}
	}
	if scanner.Err() != nil && streamErr == nil {
		streamErr = fmt.Errorf("PI 事件读取失败或事件超过大小限制")
		cancel()
	}
	waitErr := cmd.Wait()
	if streamErr != nil {
		return streamErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) && exitErr.ExitCode() == 1 {
			return ErrPartialExit
		}
		return fmt.Errorf("PI 进程异常退出，请检查模型兼容性和运行预算（上游错误详情不公开）")
	}
	return nil
}

// redactEvent works on decoded strings, so JSON escaping cannot bypass redaction.
func redactEvent(event Event, secret string) (Event, error) {
	if len(event.Data) > maxEventBytes || len(event.AgentID) > 128 {
		return Event{}, errors.New("PI 事件超过大小限制")
	}
	var value any
	if err := json.Unmarshal(event.Data, &value); err != nil {
		return Event{}, errors.New("PI 事件数据无效")
	}
	var scrub func(any) any
	scrub = func(v any) any {
		switch v := v.(type) {
		case string:
			if secret != "" {
				return strings.ReplaceAll(v, secret, "[REDACTED]")
			}
		case []any:
			for i := range v {
				v[i] = scrub(v[i])
			}
		case map[string]any:
			for k, val := range v {
				switch strings.ToLower(k) {
				case "api_key", "apikey", "authorization":
					v[k] = "[REDACTED]"
				default:
					v[k] = scrub(val)
				}
			}
		}
		return v
	}
	// IDs and enums are runtime-generated protocol fields, not model text.
	// A local gateway key such as "completed" must not corrupt lifecycle states.
	preserved := map[string]any{}
	if object, ok := value.(map[string]any); ok {
		for _, key := range []string{"id", "parent_id", "source", "target", "kind", "status", "severity"} {
			if v, exists := object[key]; exists {
				preserved[key] = v
			}
		}
	}
	cleaned := scrub(value)
	if object, ok := cleaned.(map[string]any); ok {
		for key, v := range preserved {
			object[key] = v
		}
	}
	event.Data, _ = json.Marshal(cleaned)
	return event, nil
}
