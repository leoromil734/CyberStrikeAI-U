package multiagent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cyberstrike-ai/internal/workspaceguard"

	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/cloudwego/eino/adk/middlewares/reduction"
	"github.com/cloudwego/eino/schema"
	"github.com/google/uuid"
)

// The model-facing filesystem remains read-only for reduction files. This
// backend is used only by trusted middleware, and never overwrites an original.
// Unique names also isolate reused tool-call IDs across conversations/agents.
type reductionCacheBackend struct {
	root           string
	conversationID string
}

var _ reduction.Backend = (*reductionCacheBackend)(nil)

var reductionNoticePath = regexp.MustCompile(`(?s)^<persisted-output>\s*(?:Tool result saved to:|工具结果已保存至:|(?:Output too large [^\r\n]*?\. )?Full output saved to:|输出结果过大 [^\r\n]*?\. 完整输出保存到:)\s*([^\r\n<]+)`)

// Recognize only a whole host-style notice, not a quoted marker or a pointer
// embedded in ordinary tool output. Never follow an arbitrary path from prose.
func reductionReference(text string) string {
	text = strings.TrimSpace(text)
	if !strings.HasSuffix(text, "</persisted-output>") {
		return ""
	}
	match := reductionNoticePath.FindStringSubmatch(text)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

// A legacy cache that has already lost its original cannot be repaired from the
// notice alone. Expose an actionable error rather than another circular read
// instruction, and never modify the historical file or invent its contents.
func rejectSelfReferentialReductionRead(file *os.File, path, evidenceRoot string) error {
	if evidenceRoot == "" || (filepath.Dir(path) != filepath.Join(evidenceRoot, "clear") && filepath.Dir(path) != filepath.Join(evidenceRoot, "trunc")) {
		return nil
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 8192 {
		return nil // Host notices are small; avoid reading large originals twice.
	}
	content := make([]byte, info.Size())
	_, err = file.ReadAt(content, 0) // Does not change the caller's line-read cursor.
	if err != nil && err != io.EOF {
		return err
	}
	if reductionReference(string(content)) == path {
		return fmt.Errorf("历史回读缓存已被自引用提示覆盖，不能作为原件；不要重复读取此文件。请用真实 execution_id 通过 get_tool_execution 或 query_result_artifacts 查找独立原件；若不可恢复，应如实记录证据缺失，不要重跑已完成工具或编造结果")
	}
	return nil
}

func (b *reductionCacheBackend) relative(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !workspaceguard.Within(b.root, path) {
		return "", fmt.Errorf("reduction cache path is outside the current managed root")
	}
	rel, err := filepath.Rel(b.root, path)
	if err != nil {
		return "", err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || (parts[0] != "clear" && parts[0] != "trunc") || parts[1] == "" {
		return "", fmt.Errorf("reduction cache path must be a direct clear/trunc file")
	}
	if err := workspaceguard.NoSymlink(path); err != nil {
		return "", err
	}
	return rel, nil
}

func (b *reductionCacheBackend) offloadPath(kind string) func(context.Context, *reduction.ToolDetail) (string, error) {
	return func(ctx context.Context, detail *reduction.ToolDetail) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// Clearing an already offloaded result must reuse its original, not
		// create a pointer chain or replace the original with its own notice.
		if detail != nil && detail.ToolResult != nil && len(detail.ToolResult.Parts) == 1 {
			part := detail.ToolResult.Parts[0]
			if part.Type == schema.ToolPartTypeText {
				if reference := reductionReference(part.Text); reference != "" {
					if _, err := b.relative(reference); err == nil {
						root, err := openWorkspaceRoot(b.root)
						if err != nil {
							return "", err
						}
						defer root.Close()
						rel, _ := filepath.Rel(b.root, reference)
						info, err := root.Lstat(rel)
						if err != nil || !info.Mode().IsRegular() {
							return "", fmt.Errorf("reduction original reference is unavailable; use the execution/result-artifact record rather than rereading this notice")
						}
						return reference, nil
					}
					// Foreign/untrusted references stay ordinary content in a new
					// local file. No read or write is performed at the advertised path.
				}
			}
		}
		callID := ""
		if detail != nil && detail.ToolContext != nil {
			callID = detail.ToolContext.CallID
		}
		scope := sha256.Sum256([]byte(b.conversationID + "\x00" + callID))
		return filepath.Join(b.root, kind, fmt.Sprintf("%x-%s", scope[:8], uuid.NewString())), nil
	}
}

func (b *reductionCacheBackend) Write(ctx context.Context, req *filesystem.WriteRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req == nil {
		return fmt.Errorf("reduction cache write request is nil")
	}
	rel, err := b.relative(req.FilePath)
	if err != nil {
		return err
	}
	root, err := openWorkspaceRoot(b.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, statErr := root.Lstat(rel); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("reduction cache original is not a regular file")
		}
		if reductionReference(req.Content) == req.FilePath {
			return nil // Keep the existing original, including legacy cache paths.
		}
		// Identical writes are idempotent. Conflicting data fails closed rather
		// than silently binding a different result to the same evidence path.
		if info.Size() == int64(len(req.Content)) {
			file, openErr := root.Open(rel)
			if openErr != nil {
				return openErr
			}
			content, readErr := io.ReadAll(io.LimitReader(file, int64(len(req.Content))+1))
			_ = file.Close()
			if readErr != nil {
				return readErr
			}
			if string(content) == req.Content {
				return nil
			}
		}
		return fmt.Errorf("reduction cache original already exists; refusing to overwrite it")
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if reductionReference(req.Content) == req.FilePath {
		return fmt.Errorf("reduction cache cannot create a self-referential original")
	}
	dir := filepath.Dir(rel)
	if err := root.Mkdir(dir, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := root.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("reduction cache directory must not be a symbolic link")
	}
	file, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, req.Content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = root.Remove(rel) // Only this exclusively-created incomplete file.
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	return nil
}
