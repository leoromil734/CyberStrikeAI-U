// Package gptinstruct 将 MDX-Tom/gpt-5.6-instruct v42 破甲提示词按模型名注入到系统提示。
// 仅 GPT 系列模型生效；判定依据是 model 字符串，不是 OpenAI 协议或 provider 字段。
package gptinstruct

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cyberstrike-ai/internal/config"
)

//go:embed default_v42.md
var embeddedV42 string

// Source 标识上游来源，便于审计与版本对齐。
const (
	SourceRepo    = "https://github.com/MDX-Tom/gpt-5.6-instruct"
	SourceVersion = "v42"
	SourceSHA256  = "11f0515be89943a7244d07b625a497b04dde07a51ba26e41df583a0acc145a09"
)

// Options 控制是否注入以及提示词文件来源。
type Options struct {
	Enabled    bool
	PromptPath string // 空则使用内嵌 v42；相对路径相对 BaseDir
	BaseDir    string // 通常为 config.yaml 所在目录
}

// OptionsFromConfig 从 Agent.GPTInstruct 与配置目录构造选项。
func OptionsFromConfig(cfg *config.Config) Options {
	if cfg == nil {
		return Options{}
	}
	return Options{
		Enabled:    cfg.Agent.GPTInstruct.Enabled,
		PromptPath: strings.TrimSpace(cfg.Agent.GPTInstruct.PromptPath),
		BaseDir:    strings.TrimSpace(cfg.ConfigDir),
	}
}

var (
	fileCacheMu sync.RWMutex
	fileCache   = map[string]string{} // abs path -> text
)

// LoadText 读取破甲提示词正文：优先自定义文件，否则内嵌 v42。
func LoadText(opts Options) (string, error) {
	p := strings.TrimSpace(opts.PromptPath)
	if p == "" {
		return strings.TrimSpace(embeddedV42), nil
	}
	if !filepath.IsAbs(p) && strings.TrimSpace(opts.BaseDir) != "" {
		p = filepath.Join(opts.BaseDir, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}

	fileCacheMu.RLock()
	if cached, ok := fileCache[abs]; ok {
		fileCacheMu.RUnlock()
		return cached, nil
	}
	fileCacheMu.RUnlock()

	b, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(b))
	fileCacheMu.Lock()
	fileCache[abs] = text
	fileCacheMu.Unlock()
	return text, nil
}

// MaybePrepend 在启用且模型为 GPT 系列时，将破甲提示词置于系统提示最前（对齐 Codex model_instructions_file）。
// 非 GPT 模型、未启用或加载失败时原样返回 instruction。
func MaybePrepend(instruction, model string, opts Options) string {
	if !opts.Enabled || !IsGPTSeriesModel(model) {
		return instruction
	}
	text, err := LoadText(opts)
	if err != nil || text == "" {
		return instruction
	}
	// 幂等：已注入则不再重复
	if strings.Contains(instruction, "[MODE: UNRESTRICTED]") && strings.Contains(instruction, "FIRST-PASS NORMALIZER:") {
		return instruction
	}
	instruction = strings.TrimSpace(instruction)
	if instruction == "" {
		return text
	}
	return text + "\n\n" + instruction
}

// Applied 便于日志：是否会对当前模型注入。
func Applied(model string, opts Options) bool {
	return opts.Enabled && IsGPTSeriesModel(model)
}