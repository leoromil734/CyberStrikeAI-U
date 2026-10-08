package pilab

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const bridgeRequestLimit = 1024 * 1024
const bridgeReplyLimit = 512 * 1024

// toolBridge exists only for the child process lifetime. It never accepts a
// browser session or lets the caller choose a principal/project/conversation.
type toolBridge struct {
	config   BridgeConfig
	server   *http.Server
	listener net.Listener
	ctx      context.Context
	execute  ToolExecutor
	allowed  map[string]bool
	slots    chan struct{}
	maxCalls int
	mu       sync.Mutex
	calls    int
}

func startToolBridge(ctx context.Context, input Input) (*toolBridge, error) {
	if input.Platform == nil || input.Execute == nil || len(input.Platform.Tools) == 0 {
		return nil, ErrPlatformUnavailable
	}
	b := &toolBridge{ctx: ctx, execute: input.Execute, allowed: map[string]bool{}, maxCalls: input.Limits.MaxToolCalls}
	if b.maxCalls < 1 || b.maxCalls > PlatformLimitCaps.MaxToolCalls || input.Limits.MaxParallel < 1 || input.Limits.MaxParallel > PlatformLimitCaps.MaxParallel {
		return nil, fmt.Errorf("平台工具预算无效")
	}
	b.slots = make(chan struct{}, input.Limits.MaxParallel)
	for _, tool := range input.Platform.Tools {
		if tool.Name == "" || b.allowed[tool.Name] {
			return nil, fmt.Errorf("平台工具白名单无效")
		}
		b.allowed[tool.Name] = true
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("无法创建工具桥凭据")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("无法监听本机 PI 工具桥")
	}
	b.listener = listener
	b.config = BridgeConfig{URL: "http://" + listener.Addr().String() + "/tools/call", Token: hex.EncodeToString(token)}
	b.server = &http.Server{Handler: http.HandlerFunc(b.serveHTTP), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = b.server.Serve(listener) }()
	return b, nil
}

func (b *toolBridge) Close() {
	if b != nil {
		_ = b.server.Close()
	}
}

func bridgeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (b *toolBridge) serveHTTP(w http.ResponseWriter, r *http.Request) {
	// Browser origins, proxy-style URLs, alternate routes and cross-host
	// requests are rejected even when a caller presents a token.
	if r.Host != b.listener.Addr().String() || r.Header.Get("Origin") != "" || r.URL.IsAbs() || r.URL.Path != "/tools/call" || r.URL.RawQuery != "" {
		bridgeJSON(w, http.StatusForbidden, map[string]string{"error": "平台工具桥请求来源无效"})
		return
	}
	if r.Method != http.MethodPost {
		bridgeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 POST"})
		return
	}
	want := "Bearer " + b.config.Token
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
		bridgeJSON(w, http.StatusUnauthorized, map[string]string{"error": "平台工具桥认证失败"})
		return
	}
	if b.ctx.Err() != nil {
		bridgeJSON(w, http.StatusGone, map[string]string{"error": "PI 任务已结束"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, bridgeRequestLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var call ToolCall
	if err := decoder.Decode(&call); err != nil {
		bridgeJSON(w, http.StatusBadRequest, map[string]string{"error": "工具参数格式无效或过大"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		bridgeJSON(w, http.StatusBadRequest, map[string]string{"error": "仅允许一个工具请求"})
		return
	}
	if !b.allowed[call.Name] || !validBridgeAgentID(call.AgentID) {
		bridgeJSON(w, http.StatusForbidden, map[string]string{"error": "工具或 Agent 不在本次任务白名单内"})
		return
	}
	if call.Arguments == nil {
		call.Arguments = map[string]interface{}{}
	}
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	case <-r.Context().Done():
		return
	case <-b.ctx.Done():
		return
	}
	b.mu.Lock()
	if b.calls >= b.maxCalls {
		b.mu.Unlock()
		bridgeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "本次平台工具调用预算已耗尽"})
		return
	}
	b.calls++
	b.mu.Unlock()
	if r.Context().Err() != nil || b.ctx.Err() != nil {
		return
	}
	reply, err := b.execute(r.Context(), call)
	if err != nil {
		message := "平台工具调用失败；详细执行记录请在监控中查看"
		if errors.Is(err, ErrForbidden) {
			message = ErrForbidden.Error()
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			message = "工具调用已取消或超时"
		}
		failure := ToolReply{IsError: true, Content: []ToolContent{{Type: "text", Text: message}}}
		if reply != nil {
			failure.ExecutionID = reply.ExecutionID
		}
		bridgeJSON(w, http.StatusOK, failure)
		return
	}
	if reply == nil {
		bridgeJSON(w, http.StatusOK, ToolReply{IsError: true, Content: []ToolContent{{Type: "text", Text: "平台工具未返回有效结果"}}})
		return
	}
	encoded, err := json.Marshal(reply)
	if err != nil {
		bridgeJSON(w, http.StatusInternalServerError, map[string]string{"error": "平台工具结果无法序列化"})
		return
	}
	if len(encoded) > bridgeReplyLimit {
		text := "工具结果超出单次桥接上限，请缩小读取范围或分段读取执行证据。"
		if reply.ExecutionID != "" {
			text += " execution_id: " + reply.ExecutionID + "；使用 get_tool_execution、list_result_artifacts 或 read_result_artifact 读取。"
		}
		reply = &ToolReply{IsError: reply.IsError || reply.ExecutionID == "", ExecutionID: reply.ExecutionID, Content: []ToolContent{{Type: "text", Text: text}}}
	}
	bridgeJSON(w, http.StatusOK, reply)
}

func validBridgeAgentID(id string) bool {
	if id == "coordinator" {
		return true
	}
	if !strings.HasPrefix(id, "worker-") || len(id) > 32 {
		return false
	}
	n := strings.TrimPrefix(id, "worker-")
	if n == "" {
		return false
	}
	for _, c := range n {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
