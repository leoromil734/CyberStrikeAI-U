package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func sanitizeWorkspacePathSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	s = strings.ReplaceAll(s, string(filepath.Separator), "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, "..", "__")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

// WorkspaceRootDir returns the relative workspace root for downloads and local analysis.
// Project-bound sessions share projects/<id>/; otherwise conversations/<id>/.
func WorkspaceRootDir(configuredBase, projectID, conversationID string) string {
	base := strings.TrimSpace(configuredBase)
	if base == "" {
		base = filepath.Join("tmp", "workspace")
	}
	if pid := strings.TrimSpace(projectID); pid != "" {
		return filepath.Join(base, "projects", sanitizeWorkspacePathSegment(pid))
	}
	conv := strings.TrimSpace(conversationID)
	if conv == "" {
		conv = "default"
	}
	return filepath.Join(base, "conversations", sanitizeWorkspacePathSegment(conv))
}

// EnsureWorkspace creates the workspace directory and returns its absolute path.
func EnsureWorkspace(root string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return "", fmt.Errorf("workspace abs: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", fmt.Errorf("workspace mkdir: %w", err)
	}
	return abs, nil
}

// BuildWorkspaceBlock instructs the agent to use the session workspace instead of /tmp.
func BuildWorkspaceBlock(absPath string) string {
	absPath = strings.TrimSpace(absPath)
	if absPath == "" {
		return ""
	}
	return fmt.Sprintf(`## 会话工作目录（下载与本地分析）

**必须使用以下目录**保存 curl/wget 下载的文件、临时 HTML/JS，以及 read_file/glob/grep 的检索范围：
`+"`%s`"+`

- read_file/write_file/edit_file/ls/glob/grep 的相对路径及省略的检索路径均以此目录为基准；文件读写由后端强制限制在授权目录内。
- 禁止通过绝对路径、`+"`..`"+`、符号链接访问平台源码、配置、其它项目或会话；系统 `+"`/tmp`"+` 及其它全局临时目录也不属于当前工作区。
- 技能目录与当前项目/会话的 reduction 结果缓存仅允许按提供的路径读取，禁止写入；其它结果应使用结果索引/分段读取工具获取。任务计划保存在当前工作区的 `+"`.eino`"+` 下。
- 下载示例：`+"`curl -o '%s/page.html' 'https://target/'`"+`；exec 时可将 `+"`workdir`"+` 设为该目录。
- 读取前用 glob/grep/read_file 限定当前工作区搜索；越界被拒绝后应改用工作区或结果工具，不得分段读取平台配置或切换执行工具绕过限制。`, absPath, absPath)
}
