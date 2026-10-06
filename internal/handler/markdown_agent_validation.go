package handler

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/agents"
	"gopkg.in/yaml.v3"
)

var markdownAgentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// validateMarkdownAgentWrite validates the content actually written, including raw
// Markdown requests, and prevents two files from shadowing the same agent ID.
// Callers serialize validation and file writes with writeMu.
func validateMarkdownAgentWrite(dir, filename string, content []byte) error {
	front, _, err := agents.SplitFrontMatter(string(content))
	if err != nil {
		return err
	}
	var fm agents.FrontMatter
	if err := yaml.Unmarshal([]byte(front), &fm); err != nil {
		return err
	}
	if strings.TrimSpace(fm.Name) == "" {
		return fmt.Errorf("智能体 name 不能为空")
	}
	if fm.ID != "" && !markdownAgentIDPattern.MatchString(fm.ID) {
		return fmt.Errorf("Agent ID 格式无效")
	}
	if fm.MaxIterations < 0 {
		return fmt.Errorf("最大迭代数不能为负数")
	}
	sub, err := agents.ParseMarkdownSubAgent(filename, string(content))
	if err != nil {
		return err
	}
	if !markdownAgentIDPattern.MatchString(sub.ID) {
		return fmt.Errorf("Agent ID 必须为 1–64 个字母、数字、连字符或下划线，且以字母或数字开头")
	}
	if err := validateRoleName(sub.Name); err != nil {
		return fmt.Errorf("智能体名称无效: %w", err)
	}
	if strings.TrimSpace(sub.Instruction) == "" {
		return fmt.Errorf("智能体指令不能为空")
	}
	files, err := agents.LoadMarkdownAgentFiles(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if filepath.Base(file.Filename) != filepath.Base(filename) && file.Config.ID == sub.ID {
			return fmt.Errorf("Agent ID 已被文件 %s 使用", file.Filename)
		}
	}
	return nil
}
