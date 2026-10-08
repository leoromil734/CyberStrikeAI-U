package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/pilab"
	"cyberstrike-ai/internal/skillpackage"
	"cyberstrike-ai/internal/workspaceguard"
)

var piPlatformSkillID = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

const piPlatformMaxSkillBytes = 1 << 20

func piPlatformFileTool(name string) bool {
	switch name {
	case "load_skill", "read_skill_file", "read_file", "write_file", "list_files":
		return true
	}
	return false
}
func piPlatformFileDefinitions() []pilab.ToolDefinition {
	str := func(description string) map[string]interface{} {
		return map[string]interface{}{"type": "string", "description": description}
	}
	def := func(name, description string, properties map[string]interface{}, required ...string) pilab.ToolDefinition {
		schema := map[string]interface{}{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			schema["required"] = required
		}
		return pilab.ToolDefinition{Name: name, Description: description, InputSchema: schema}
	}
	return []pilab.ToolDefinition{
		def("load_skill", "渐进加载已登记技能正文。任务开始先加载 pentest-agent-os，再按角色加载当前阶段技能。", map[string]interface{}{"name": str("技能名称，不是路径")}, "name"),
		def("read_skill_file", "读取技能包内相对路径引用。仅限当前技能目录，禁止符号链接。", map[string]interface{}{"name": str("技能名称"), "path": str("技能包内相对文件路径，例如 references/checklist.md")}, "name", "path"),
		def("read_file", "读取当前工作目录或只读技能/证据文件。offset 与 limit 单位为字节，不是行；大输出按 offset 分段读取。", map[string]interface{}{"path": str("当前工作目录相对路径，或授权只读根内路径"), "offset": map[string]interface{}{"type": "integer", "minimum": 0}, "limit": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 12000}}, "path"),
		def("write_file", "在当前工作目录内创建或覆盖 UTF-8 文本，最大 1 MiB。技能/证据目录只读。", map[string]interface{}{"path": str("当前工作目录内文件路径"), "content": str("文件内容")}, "path", "content"),
		def("list_files", "列出授权目录的直接子项（最多 256 项，不递归、不跟随符号链接）。", map[string]interface{}{"path": str("目录路径，默认为当前工作目录")}),
	}
}

func piPlatformPath(path string, relative bool) error {
	if strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("文件路径无效")
	}
	for _, part := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if part == ".." {
			return fmt.Errorf("禁止目录穿越")
		}
	}
	if relative && (path == "" || path == "." || filepath.IsAbs(path) || strings.Contains(path, ":") || strings.HasPrefix(path, "/") || strings.Contains(path, "\\")) {
		return fmt.Errorf("技能文件必须使用包内相对路径")
	}
	if filepath.VolumeName(path) != "" && !filepath.IsAbs(path) {
		return fmt.Errorf("禁止驱动器相对路径")
	}
	if filepath.Separator == '\\' && (strings.HasPrefix(path, "\\") || strings.HasPrefix(path, "/")) && !filepath.IsAbs(path) {
		return fmt.Errorf("禁止未指定驱动器的绝对路径")
	}
	return nil
}

// Pin every component, checking identity before/after OpenRoot. This closes the
// root acquisition race (NoSymlink followed by a plain os.Open is insufficient).
func piPlatformOpenRoot(path string) (*os.Root, error) {
	abs, err := filepath.Abs(path)
	if err != nil || path == "" {
		return nil, fmt.Errorf("文件根目录不可用")
	}
	if err = piPlatformPath(abs, false); err != nil {
		return nil, err
	}
	if err = workspaceguard.NoSymlink(abs); err != nil {
		return nil, fmt.Errorf("禁止符号链接")
	}
	volume := filepath.VolumeName(abs)
	root, err := os.OpenRoot(volume + string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("文件根目录不可用")
	}
	parts := strings.TrimLeft(filepath.Clean(abs)[len(volume):], string(filepath.Separator))
	next, err := piPlatformDirectory(root, parts, false)
	root.Close()
	return next, err
}
func piPlatformDirectory(root *os.Root, path string, create bool) (*os.Root, error) {
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, fmt.Errorf("目录不可用")
	}
	for _, part := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		if part == ".." {
			current.Close()
			return nil, fmt.Errorf("禁止目录穿越")
		}
		before, err := current.Lstat(part)
		if create && os.IsNotExist(err) {
			if err = current.Mkdir(part, 0700); err != nil && !os.IsExist(err) {
				current.Close()
				return nil, fmt.Errorf("目录创建失败")
			}
			before, err = current.Lstat(part)
		}
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			current.Close()
			return nil, fmt.Errorf("目录不存在或包含符号链接")
		}
		next, err := current.OpenRoot(part)
		current.Close()
		if err != nil {
			return nil, fmt.Errorf("目录不可用")
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			next.Close()
			return nil, fmt.Errorf("目录在访问时发生变化")
		}
		current = next
	}
	return current, nil
}
func piPlatformRegularFile(root *os.Root, path string, write bool) (*os.File, error) {
	parent, err := piPlatformDirectory(root, filepath.Dir(path), write)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	base := filepath.Base(path)
	before, err := parent.Lstat(base)
	exists := err == nil
	if err != nil && !(write && os.IsNotExist(err)) {
		return nil, fmt.Errorf("文件不存在或不可访问")
	}
	if exists && !before.Mode().IsRegular() {
		return nil, fmt.Errorf("仅支持普通文件，禁止符号链接")
	}
	flags := os.O_RDONLY
	if write {
		flags = os.O_WRONLY | os.O_CREATE
		if !exists {
			flags |= os.O_EXCL
		}
	}
	file, err := parent.OpenFile(base, flags, 0600)
	if err != nil {
		return nil, fmt.Errorf("文件不可访问")
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || (exists && !os.SameFile(before, after)) {
		file.Close()
		return nil, fmt.Errorf("文件在访问时发生变化")
	}
	if !workspaceguard.SingleLink(file) {
		file.Close()
		return nil, fmt.Errorf("禁止硬链接或无法核实文件链接数")
	}
	return file, nil
}

// Use the existing skillpackage manifest parser/validator with rooted I/O.
// LoadSkill/ReadPackageFile currently use pathname-based os.ReadFile internally;
// invoking them directly would reopen a symlink race after boundary validation.
func piPlatformReadSkill(rootPath, name, path string) ([]byte, error) {
	if len(name) > 64 || !piPlatformSkillID.MatchString(name) {
		return nil, fmt.Errorf("技能名称无效")
	}
	if err := piPlatformPath(path, true); err != nil {
		return nil, err
	}
	root, err := piPlatformOpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := piPlatformRegularFile(root, filepath.Join(name, filepath.FromSlash(path)), false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, piPlatformMaxSkillBytes+1))
	if err != nil || len(data) > piPlatformMaxSkillBytes {
		return nil, fmt.Errorf("技能文件不可读或超过 1 MiB")
	}
	return data, nil
}
func piPlatformSkills(path string) ([]pilab.SkillInfo, error) {
	root, err := piPlatformOpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2049)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 2048 {
		return nil, fmt.Errorf("技能目录数量超过上限")
	}
	out := []pilab.SkillInfo{}
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !piPlatformSkillID.MatchString(name) {
			continue
		}
		data, err := piPlatformReadSkill(path, name, "SKILL.md")
		if err != nil {
			continue
		}
		manifest, _, err := skillpackage.ParseSkillMD(data)
		if err != nil || skillpackage.ValidateAgentSkillManifestInPackage(manifest, name) != nil {
			continue
		}
		out = append(out, pilab.SkillInfo{Name: name, Description: manifest.Description})
		found = found || name == "pentest-agent-os"
	}
	if !found {
		return nil, fmt.Errorf("pentest-agent-os 技能不可用")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (s *piPlatformRun) fileRoot(path string, write bool) (*os.Root, string, error) {
	if err := piPlatformPath(path, false); err != nil {
		return nil, "", err
	}
	abs, err := s.policy.Resolve(path, write)
	if err != nil {
		return nil, "", fmt.Errorf("文件不在当前授权工作目录或只读根内，或包含符号链接")
	}
	rootPath := s.policy.Workspace
	if !workspaceguard.Within(rootPath, abs) {
		rootPath = ""
	}
	for _, ro := range s.policy.ReadOnlyRoots {
		if workspaceguard.Within(ro, abs) {
			if write {
				return nil, "", fmt.Errorf("技能和证据目录只读")
			}
			if len(ro) > len(rootPath) {
				rootPath = ro
			}
		}
	}
	if rootPath == "" {
		return nil, "", fmt.Errorf("文件访问越界")
	}
	rel, err := filepath.Rel(rootPath, abs)
	if err != nil {
		return nil, "", fmt.Errorf("文件访问越界")
	}
	root, err := piPlatformOpenRoot(rootPath)
	return root, rel, err
}
func (s *piPlatformRun) fileTool(ctx context.Context, name string, args map[string]interface{}) (*mcp.ToolResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	text := func(value string) *mcp.ToolResult {
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: value}}}
	}
	path, _ := args["path"].(string)
	if name == "load_skill" || name == "read_skill_file" {
		skill, _ := args["name"].(string)
		allowed := false
		for _, info := range s.skills {
			allowed = allowed || info.Name == skill
		}
		if !allowed {
			return nil, fmt.Errorf("技能未登记或名称无效")
		}
		if name == "load_skill" {
			path = "SKILL.md"
		}
		data, err := piPlatformReadSkill(s.cfg.SkillsDir, skill, path)
		if err != nil {
			return nil, err
		}
		if name == "load_skill" {
			manifest, body, err := skillpackage.ParseSkillMD(data)
			if err != nil || skillpackage.ValidateAgentSkillManifestInPackage(manifest, skill) != nil {
				return nil, fmt.Errorf("技能元数据无效")
			}
			skillDir, err := filepath.Abs(filepath.Join(s.cfg.SkillsDir, skill))
			if err != nil {
				return nil, fmt.Errorf("无法确定技能目录")
			}
			// This path comes from the validated server-side skill registry, not
			// from the skill body or model arguments. JSON quoting handles spaces
			// and Windows separators without suggesting shell-specific quoting.
			encodedDir, _ := json.Marshal(skillDir)
			return text("# " + skill + "\n\n平台提供的只读技能目录（绝对路径，JSON 字符串）：" + string(encodedDir) + "\n技能正文中的 scripts/ 等相对路径以此目录为基准；如需执行脚本，使用已授权的 exec 工具，并按其命令语法引用路径。技能目录只读，输出写入当前任务工作目录。\n\n## 技能正文\n\n" + body), nil
		}
		return text(string(data)), nil
	}
	if name != "list_files" && strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("path 不能为空")
	}
	root, rel, err := s.fileRoot(path, name == "write_file")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if name == "list_files" {
		dirRoot, err := piPlatformDirectory(root, rel, false)
		if err != nil {
			return nil, err
		}
		defer dirRoot.Close()
		dir, err := dirRoot.Open(".")
		if err != nil {
			return nil, fmt.Errorf("目录不可读")
		}
		defer dir.Close()
		entries, err := dir.ReadDir(257)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("目录不可读")
		}
		names := []string{}
		truncated := len(entries) > 256
		if truncated {
			entries = entries[:256]
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			abs := filepath.Join(root.Name(), rel, entry.Name())
			if _, err := s.policy.Resolve(abs, false); err != nil {
				continue
			}
			item := entry.Name()
			if entry.IsDir() {
				item += "/"
			}
			names = append(names, item)
		}
		sort.Strings(names)
		data, _ := json.Marshal(map[string]interface{}{"entries": names, "truncated": truncated})
		return text(string(data)), nil
	}
	file, err := piPlatformRegularFile(root, rel, name == "write_file")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if name == "write_file" {
		content, ok := args["content"].(string)
		if !ok || len(content) > 1<<20 {
			return nil, fmt.Errorf("content 必须是最多 1 MiB 的文本")
		}
		if err = file.Truncate(0); err != nil {
			return nil, fmt.Errorf("文件写入失败")
		}
		if _, err = file.WriteString(content); err != nil {
			return nil, fmt.Errorf("文件写入失败")
		}
		return text("文件已保存。"), nil
	}
	offset, err := piPlatformInteger(args, "offset", 0, 0, 1<<40)
	if err != nil {
		return nil, err
	}
	limit, err := piPlatformInteger(args, "limit", 8000, 1, 12000)
	if err != nil {
		return nil, err
	}
	if _, err = file.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("文件偏移量无效")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, fmt.Errorf("文件读取失败")
	}
	return text(string(data)), nil
}
func piPlatformInteger(args map[string]interface{}, key string, fallback, min, max int64) (int64, error) {
	value, exists := args[key]
	if !exists {
		return fallback, nil
	}
	number, ok := value.(float64)
	if !ok || number < float64(min) || number > float64(max) || number != float64(int64(number)) {
		return 0, fmt.Errorf("%s 必须是允许范围内的整数", key)
	}
	return int64(number), nil
}
