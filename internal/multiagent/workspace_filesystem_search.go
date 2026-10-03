package multiagent

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cloudwego/eino/adk/filesystem"
)

func validateWorkspaceGlob(pattern string) error {
	if err := validateWorkspacePath(pattern); err != nil {
		return err
	}
	if filepath.IsAbs(pattern) || filepath.VolumeName(pattern) != "" || strings.HasPrefix(pattern, "/") || strings.HasPrefix(pattern, "\\") {
		return workspaceBoundaryError()
	}
	if !doublestar.ValidatePattern(pattern) {
		return fmt.Errorf("invalid glob pattern")
	}
	return nil
}

// walk only uses os.Root.FS, including when WalkDir reopens a directory. DirEntry
// metadata and all file contents are read through the same root. Symlinks are
// skipped, and even a concurrent directory-to-symlink swap cannot leave root.
func walkWorkspace(ctx context.Context, root *os.Root, relative string, visit func(string, fs.FileInfo) error) error {
	return fs.WalkDir(root.FS(), filepath.ToSlash(relative), func(name string, entry fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := root.Lstat(filepath.FromSlash(name))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		return visit(name, info)
	})
}

func (b *workspaceFilesystem) GlobInfo(ctx context.Context, req *filesystem.GlobInfoRequest) ([]filesystem.FileInfo, error) {
	if req == nil {
		return nil, fmt.Errorf("glob request is required")
	}
	if err := validateWorkspaceGlob(req.Pattern); err != nil {
		return nil, err
	}
	root, relative, absolute, err := b.resolve(ctx, req.Path, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var out []filesystem.FileInfo
	err = walkWorkspace(ctx, root, relative, func(name string, info fs.FileInfo) error {
		rel, err := filepath.Rel(relative, filepath.FromSlash(name))
		if err != nil {
			return err
		}
		if b.hiddenPath(filepath.Join(absolute, rel)) {
			if info.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel == "." {
			return nil
		}
		matched, err := doublestar.Match(req.Pattern, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if matched {
			out = append(out, workspaceFileInfo(filepath.Join(absolute, rel), info))
		}
		return nil
	})
	if err != nil {
		return nil, err // Never return partially collected results after an error.
	}
	return out, nil
}

// Type aliases cover the common ripgrep type names used by Eino. Unknown types
// fail explicitly rather than broadening a search or invoking an unguarded rg.
var workspaceGrepFileTypes = map[string]string{
	"go": "*.go", "js": "*.{js,jsx,mjs,cjs}", "ts": "*.{ts,tsx,mts,cts}",
	"py": "*.{py,pyi,pyw}", "rust": "*.rs", "java": "*.java", "kotlin": "*.{kt,kts}",
	"c": "*.{c,h}", "cpp": "*.{c,cc,cpp,cxx,h,hh,hpp,hxx}", "cs": "*.cs", "swift": "*.swift",
	"html": "*.{html,htm,xhtml}", "css": "*.css", "scss": "*.scss", "sass": "*.sass", "vue": "*.vue",
	"json": "*.{json,jsonl}", "yaml": "*.{yaml,yml}", "xml": "*.{xml,xsd,xsl,svg}",
	"md": "*.{md,markdown,mdown,mkd}", "txt": "*.txt", "text": "*.txt", "log": "*.log",
	"sh": "*.{sh,bash,zsh,ksh}", "bash": "*.bash", "zsh": "*.zsh", "fish": "*.fish", "ps": "*.{ps1,psm1,psd1}",
	"sql": "*.sql", "toml": "*.toml", "ini": "*.ini", "conf": "*.{conf,config}",
	"php": "*.{php,php3,php4,php5,phtml}", "ruby": "*.{rb,ruby,rake,gemspec}", "perl": "*.{pl,pm,t}",
	"lua": "*.lua", "r": "*.{r,R,Rmd}", "dart": "*.dart", "elixir": "*.{ex,exs}", "erlang": "*.{erl,hrl}",
	"proto": "*.proto", "docker": "{Dockerfile,Dockerfile.*,*.dockerfile}", "make": "{Makefile,makefile,GNUmakefile,*.mk}",
	"cmake": "{CMakeLists.txt,*.cmake}", "lock": "*.lock", "csv": "*.csv", "ipynb": "*.ipynb",
}

func workspaceGrepGlob(pattern, relative string) bool {
	if pattern == "" {
		return true
	}
	exclude := strings.HasPrefix(pattern, "!")
	pattern = strings.TrimPrefix(pattern, "!")
	matched, _ := doublestar.Match(pattern, filepath.ToSlash(relative))
	if !matched {
		matched, _ = doublestar.Match(pattern, filepath.Base(relative))
	}
	return matched != exclude
}

func (b *workspaceFilesystem) GrepRaw(ctx context.Context, req *filesystem.GrepRequest) ([]filesystem.GrepMatch, error) {
	if req == nil || req.Pattern == "" {
		return nil, fmt.Errorf("grep pattern is required")
	}
	if err := validateWorkspaceGlob(strings.TrimPrefix(req.Glob, "!")); err != nil {
		return nil, err
	}
	typePattern := ""
	if req.FileType != "" {
		var ok bool
		typePattern, ok = workspaceGrepFileTypes[req.FileType]
		if !ok {
			return nil, fmt.Errorf("unsupported file type: %q; use glob instead", req.FileType)
		}
	}
	pattern := req.Pattern
	if req.CaseInsensitive {
		pattern = "(?i)" + pattern
	}
	if req.EnableMultiline {
		pattern = "(?ms)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid grep pattern: %w", err)
	}
	root, relative, absolute, err := b.resolve(ctx, req.Path, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var out []filesystem.GrepMatch
	err = walkWorkspace(ctx, root, relative, func(name string, info fs.FileInfo) error {
		rel, err := filepath.Rel(relative, filepath.FromSlash(name))
		if err != nil {
			return err
		}
		if b.hiddenPath(filepath.Join(absolute, rel)) {
			if info.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		filterPath := rel
		if filterPath == "." {
			filterPath = filepath.Base(absolute)
		}
		if !workspaceGrepGlob(req.Glob, filterPath) || !workspaceGrepGlob(typePattern, filterPath) {
			return nil
		}
		file, err := workspaceRegularFile(root, filepath.FromSlash(name), os.O_RDONLY)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(data) == 0 || strings.IndexByte(string(data), 0) >= 0 {
			return nil // Match ripgrep's default exclusion of binary files.
		}
		out = append(out, workspaceGrepLines(string(data), filepath.Join(absolute, rel), re, req)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func workspaceGrepLines(text, path string, re *regexp.Regexp, req *filesystem.GrepRequest) []filesystem.GrepMatch {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	matched := make([]bool, len(lines))
	if req.EnableMultiline {
		starts := make([]int, len(lines))
		for i := 1; i < len(lines); i++ {
			starts[i] = starts[i-1] + len(lines[i-1]) + 1
		}
		for _, span := range re.FindAllStringIndex(text, -1) {
			first := sort.Search(len(starts), func(i int) bool { return starts[i] > span[0] }) - 1
			lastOffset := max(span[0], span[1]-1)
			last := sort.Search(len(starts), func(i int) bool { return starts[i] > lastOffset }) - 1
			for i := first; i <= last; i++ {
				matched[i] = true
			}
		}
	} else {
		for i, line := range lines {
			matched[i] = re.MatchString(strings.TrimSuffix(line, "\r"))
		}
	}
	selected := make([]bool, len(lines))
	before := min(max(req.BeforeLines, 0), len(lines))
	after := min(max(req.AfterLines, 0), len(lines))
	for i, match := range matched {
		if match {
			for j := max(0, i-before); j <= min(len(lines)-1, i+after); j++ {
				selected[j] = true
			}
		}
	}
	var out []filesystem.GrepMatch
	for i, include := range selected {
		if include {
			out = append(out, filesystem.GrepMatch{Path: path, Line: i + 1, Content: strings.TrimSuffix(lines[i], "\r")})
		}
	}
	return out
}
