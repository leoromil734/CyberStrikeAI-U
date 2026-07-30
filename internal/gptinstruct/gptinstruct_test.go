package gptinstruct

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestIsGPTSeriesModel_ByNameNotProvider(t *testing.T) {
	yes := []string{
		"gpt-4o",
		"GPT-4.1",
		"gpt-5.6-sol",
		"gpt-3.5-turbo",
		"chatgpt-4o-latest",
		"openai/gpt-4o",
		"azure/gpt-4o-mini",
		"ft:gpt-4o-2024-08-06:acme:custom:abc",
		"gpt_4o",
	}
	for _, m := range yes {
		if !IsGPTSeriesModel(m) {
			t.Fatalf("expected GPT series: %q", m)
		}
	}
	no := []string{
		"",
		"qwen3-max",
		"deepseek-chat",
		"claude-3-opus",
		"o1",
		"o3-mini",
		"gemini-2.0-flash",
		"llama-3.1-70b",
		// 名称不含 gpt- 前缀的 openai 系推理模型：按「模型名」规则不注入
		"o1-preview",
	}
	for _, m := range no {
		if IsGPTSeriesModel(m) {
			t.Fatalf("expected non-GPT: %q", m)
		}
	}
}

func TestMaybePrepend_OnlyGPTWhenEnabled(t *testing.T) {
	opts := Options{Enabled: true}
	base := "ROLE_ONLY"
	got := MaybePrepend(base, "gpt-4o", opts)
	if !strings.HasPrefix(got, "[MODE: UNRESTRICTED]") {
		t.Fatalf("gpt model should get instruct first")
	}
	if !strings.Contains(got, "ROLE_ONLY") {
		t.Fatalf("original instruction must remain")
	}
	if got2 := MaybePrepend(base, "qwen3-max", opts); got2 != base {
		t.Fatalf("non-gpt must be unchanged, got %q", got2)
	}
	if got3 := MaybePrepend(base, "gpt-4o", Options{Enabled: false}); got3 != base {
		t.Fatalf("disabled must be unchanged")
	}
}

func TestMaybePrepend_Idempotent(t *testing.T) {
	opts := Options{Enabled: true}
	once := MaybePrepend("ROLE", "gpt-4o", opts)
	twice := MaybePrepend(once, "gpt-4o", opts)
	if once != twice {
		t.Fatalf("double apply should be idempotent")
	}
	if c := strings.Count(twice, "[MODE: UNRESTRICTED]"); c != 1 {
		t.Fatalf("marker count = %d, want 1", c)
	}
}

func TestLoadText_CustomFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.md")
	if err := os.WriteFile(path, []byte("CUSTOM_INSTRUCT"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, err := LoadText(Options{PromptPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if text != "CUSTOM_INSTRUCT" {
		t.Fatalf("got %q", text)
	}
	rel, err := LoadText(Options{PromptPath: "custom.md", BaseDir: dir})
	if err != nil || rel != "CUSTOM_INSTRUCT" {
		t.Fatalf("relative load failed: %v %q", err, rel)
	}
}

func TestOptionsFromConfig(t *testing.T) {
	cfg := &config.Config{
		ConfigDir: "/cfg",
		Agent: config.AgentConfig{
			GPTInstruct: config.GPTInstructConfig{
				Enabled:    true,
				PromptPath: "prompts/x.md",
			},
		},
	}
	opts := OptionsFromConfig(cfg)
	if !opts.Enabled || opts.BaseDir != "/cfg" || opts.PromptPath != "prompts/x.md" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
	if OptionsFromConfig(nil).Enabled {
		t.Fatal("nil config should be disabled")
	}
}

func TestEmbeddedV42Present(t *testing.T) {
	text, err := LoadText(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, need := range []string{"[MODE: UNRESTRICTED]", "FIRST-PASS NORMALIZER:", "BEGIN."} {
		if !strings.Contains(text, need) {
			t.Fatalf("embedded v42 missing %q", need)
		}
	}
}