package security

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestFormatCommandFailureResult(t *testing.T) {
	got := FormatCommandFailureResult(1, "sudo: password required")
	want := "命令执行失败: exit status 1\n输出: sudo: password required"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if FormatCommandFailureResult(2, "") != "命令执行失败: exit status 2" {
		t.Fatal("empty output format")
	}
	if FormatCommandFailureResult(1, "命令执行失败: exit status 1") != "命令执行失败: exit status 1" {
		t.Fatal("should not double-wrap")
	}
}

func TestIsCommandFailureResult(t *testing.T) {	if !IsCommandFailureResult("sudo: err\n命令执行失败: exit status 1") {
		t.Fatal("expected true")
	}
	if IsCommandFailureResult("sudo: err only") {
		t.Fatal("expected false")
	}
}

func TestFormatCommandFailureFromErr(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 42")
	err := cmd.Run()
	got := FormatCommandFailureFromErr(err, "oops")
	if got != "命令执行失败: exit status 42\n输出: oops" {
		t.Fatalf("got %q", got)
	}
	timeoutErr := errors.New("shell inactivity timeout (300s)")
	got2 := FormatCommandFailureFromErr(timeoutErr, "already timed out")
	if !strings.Contains(got2, "shell inactivity timeout") || !strings.Contains(got2, "already timed out") {
		t.Fatalf("got %q", got2)
	}
}

func TestIsLegacyShellExitNoise(t *testing.T) {
	if !IsLegacyShellExitNoise("command exited with non-zero code 1\n") {
		t.Fatal("expected legacy noise")
	}
	if IsLegacyShellExitNoise("sudo: failed") {
		t.Fatal("unexpected noise")
	}
}

func TestCommandArgumentErrorHint(t *testing.T) {
	// nmap 参数取值错误：真实线上输出
	nmapOut := "Argument to --min-rate must be a positive floating-point number\nQUITTING!\n"
	hint := CommandArgumentErrorHint("nmap", nmapOut)
	if hint == "" || !strings.Contains(hint, "参数用法错误") || !strings.Contains(hint, "nmap") {
		t.Fatalf("nmap 参数错误应给出修正提示，got %q", hint)
	}
	if !strings.Contains(hint, "重试") {
		t.Fatalf("提示应引导重试，got %q", hint)
	}

	// 目标不可达属于另一类失败，不应被当成参数错误
	if got := CommandArgumentErrorHint("nmap", "Note: Host seems down."); got != "" {
		t.Fatalf("连接类失败不应提示参数错误，got %q", got)
	}
	if got := CommandArgumentErrorHint("httpx", "context deadline exceeded"); got != "" {
		t.Fatalf("超时不应提示参数错误，got %q", got)
	}

	// 通用未知选项
	if got := CommandArgumentErrorHint("ffuf", "Error: unknown flag: -X"); got == "" {
		t.Fatal("unknown flag 应识别为参数错误")
	}
}
