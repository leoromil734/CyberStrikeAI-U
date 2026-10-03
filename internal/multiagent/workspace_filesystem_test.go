package multiagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"cyberstrike-ai/internal/workspaceguard"

	"github.com/cloudwego/eino/adk/filesystem"
)

type workspaceFSFixture struct {
	ctx                                                                      context.Context
	backend                                                                  filesystem.Backend
	policy                                                                   *workspaceguard.Policy
	workspace, sibling, skills, reduction, otherReduction, platform, runtime string
}

func newWorkspaceFSFixture(t *testing.T) workspaceFSFixture {
	t.Helper()
	base := t.TempDir()
	f := workspaceFSFixture{
		workspace:      filepath.Join(base, "workspace", "projects", "one"),
		sibling:        filepath.Join(base, "workspace", "projects", "two"),
		skills:         filepath.Join(base, "skills"),
		reduction:      filepath.Join(base, "reduction", "projects", "one"),
		otherReduction: filepath.Join(base, "reduction", "projects", "two"),
		platform:       filepath.Join(base, "platform"),
		runtime:        filepath.Join(base, "runtime"),
	}
	for _, dir := range []string{f.workspace, f.sibling, f.skills, f.reduction, f.otherReduction, f.platform, f.runtime} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.policy = &workspaceguard.Policy{Workspace: f.workspace, ReadOnlyRoots: []string{f.skills, f.reduction}, RuntimeReadOnlyRoots: []string{f.runtime}}
	f.ctx = workspaceguard.WithPolicy(context.Background(), f.policy)
	f.backend = wrapModelFilesystem(f.ctx, nil)
	return f
}

func writeWorkspaceFixture(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertWorkspaceDenied(t *testing.T, b filesystem.Backend, ctx context.Context, path string) {
	t.Helper()
	checks := []struct {
		name string
		call func() error
	}{
		{"read", func() error {
			_, err := b.Read(ctx, &filesystem.ReadRequest{FilePath: path, Offset: 2, Limit: 1})
			return err
		}},
		{"write", func() error { return b.Write(ctx, &filesystem.WriteRequest{FilePath: path, Content: "modified"}) }},
		{"edit", func() error {
			return b.Edit(ctx, &filesystem.EditRequest{FilePath: path, OldString: "canary", NewString: "modified"})
		}},
		{"ls", func() error { _, err := b.LsInfo(ctx, &filesystem.LsInfoRequest{Path: path}); return err }},
		{"glob", func() error {
			_, err := b.GlobInfo(ctx, &filesystem.GlobInfoRequest{Path: path, Pattern: "**/*"})
			return err
		}},
		{"grep", func() error {
			_, err := b.GrepRaw(ctx, &filesystem.GrepRequest{Path: path, Pattern: "canary"})
			return err
		}},
	}
	for _, check := range checks {
		if err := check.call(); err == nil {
			t.Errorf("%s unexpectedly allowed path %q", check.name, path)
		}
	}
}

func TestWorkspaceFilesystemRejectsOutsideAndSegmentedConfig(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	config := filepath.Join(f.platform, "config.yaml")
	writeWorkspaceFixture(t, config, "canary line 1\ncanary line 2\ncanary line 3")
	writeWorkspaceFixture(t, filepath.Join(f.platform, "internal", "source.go"), "canary platform source")
	for _, offset := range []int{-1, 0, 1, 2, 3, 999} {
		got, err := f.backend.Read(f.ctx, &filesystem.ReadRequest{FilePath: config, Offset: offset, Limit: 1})
		if err == nil || got != nil {
			t.Fatalf("segmented config read offset %d: %+v, %v", offset, got, err)
		}
	}
	paths := []string{
		config, f.platform, filepath.Join(f.platform, "internal"), f.sibling, f.otherReduction, f.runtime,
		"../two/report.txt", "..", "sub/../../config.yaml", `sub\..\..\config.yaml`,
		f.workspace + string(filepath.Separator) + ".." + string(filepath.Separator) + "one" + string(filepath.Separator) + "file.txt",
		filepath.VolumeName(f.workspace) + string(filepath.Separator),
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) { assertWorkspaceDenied(t, f.backend, f.ctx, path) })
	}
	for _, pattern := range []string{"../**", "**/../config.yaml", filepath.ToSlash(config)} {
		if _, err := f.backend.GlobInfo(f.ctx, &filesystem.GlobInfoRequest{Pattern: pattern}); err == nil {
			t.Fatalf("allowed unsafe glob %q", pattern)
		}
		if _, err := f.backend.GrepRaw(f.ctx, &filesystem.GrepRequest{Pattern: "canary", Glob: pattern}); err == nil {
			t.Fatalf("allowed unsafe grep glob %q", pattern)
		}
	}
	data, err := os.ReadFile(config)
	if err != nil || string(data) != "canary line 1\ncanary line 2\ncanary line 3" {
		t.Fatal("outside config fixture was modified")
	}
}

func TestWorkspaceFilesystemNormalReadWriteEditAndSearch(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	b, ctx := f.backend, f.ctx
	if err := b.Write(ctx, &filesystem.WriteRequest{FilePath: "downloads/app.js", Content: "before\nconst TOKEN = 'value';\nafter\nlast\n"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Edit(ctx, &filesystem.EditRequest{FilePath: "downloads/app.js", OldString: "value", NewString: "new value"}); err != nil {
		t.Fatal(err)
	}
	got, err := b.Read(ctx, &filesystem.ReadRequest{FilePath: "downloads/app.js", Offset: 2, Limit: 1})
	if err != nil || got.Content != "const TOKEN = 'new value';" {
		t.Fatalf("read: %+v %v", got, err)
	}
	entries, err := b.LsInfo(ctx, &filesystem.LsInfoRequest{Path: "downloads"})
	if err != nil || len(entries) != 1 || entries[0].Path != filepath.Join(f.workspace, "downloads", "app.js") || entries[0].Size == 0 {
		t.Fatalf("ls: %+v %v", entries, err)
	}
	writeWorkspaceFixture(t, filepath.Join(f.sibling, "private.js"), "canary sibling")
	writeWorkspaceFixture(t, filepath.Join(f.workspace, "binary.js"), "TOKEN\x00binary")
	globReq := &filesystem.GlobInfoRequest{Pattern: "**/*.js"}
	files, err := b.GlobInfo(ctx, globReq)
	if err != nil || len(files) != 2 || globReq.Path != "" {
		t.Fatalf("default glob: %+v %v", files, err)
	}
	for _, file := range files {
		if !workspaceguard.Within(f.workspace, file.Path) {
			t.Fatalf("glob escaped: %+v", file)
		}
	}
	matches, err := b.GrepRaw(ctx, &filesystem.GrepRequest{Pattern: "token.*value", CaseInsensitive: true, Glob: "*.js", FileType: "js", BeforeLines: 1, AfterLines: 1})
	if err != nil || len(matches) != 3 || matches[0].Line != 1 || matches[2].Content != "after" {
		t.Fatalf("grep context/type/glob: %+v %v", matches, err)
	}
	matches, err = b.GrepRaw(ctx, &filesystem.GrepRequest{Pattern: "before.*after", EnableMultiline: true, Glob: "**/*.js"})
	if err != nil || len(matches) != 3 || matches[1].Line != 2 {
		t.Fatalf("multiline grep: %+v %v", matches, err)
	}
	matches, err = b.GrepRaw(ctx, &filesystem.GrepRequest{Path: "downloads/app.js", Pattern: "TOKEN", FileType: "js"})
	if err != nil || len(matches) != 1 {
		t.Fatalf("grep file: %+v %v", matches, err)
	}
	matches, err = b.GrepRaw(ctx, &filesystem.GrepRequest{Pattern: "TOKEN", Glob: "!*.js"})
	if err != nil || len(matches) != 0 {
		t.Fatalf("negative glob: %+v %v", matches, err)
	}
	if _, err := b.GrepRaw(ctx, &filesystem.GrepRequest{Pattern: "["}); err == nil {
		t.Fatal("invalid regex accepted")
	}
	if _, err := b.GrepRaw(ctx, &filesystem.GrepRequest{Pattern: "TOKEN", FileType: "unknown-type"}); err == nil {
		t.Fatal("unknown type broadened search")
	}
}

func TestWorkspaceFilesystemReadOnlySkillsAndCurrentReduction(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	for _, root := range []string{f.skills, f.reduction} {
		path := filepath.Join(root, "artifact.txt")
		writeWorkspaceFixture(t, path, "read only evidence")
		got, err := f.backend.Read(f.ctx, &filesystem.ReadRequest{FilePath: path})
		if err != nil || got.Content != "read only evidence" {
			t.Fatalf("readonly read: %+v %v", got, err)
		}
		if err := f.backend.Write(f.ctx, &filesystem.WriteRequest{FilePath: path, Content: "mutated"}); err == nil {
			t.Fatal("readonly write allowed")
		}
		if err := f.backend.Write(f.ctx, &filesystem.WriteRequest{FilePath: filepath.Join(root, "new.txt"), Content: "mutated"}); err == nil {
			t.Fatal("readonly create allowed")
		}
		if err := f.backend.Edit(f.ctx, &filesystem.EditRequest{FilePath: path, OldString: "evidence", NewString: "mutated"}); err == nil {
			t.Fatal("readonly edit allowed")
		}
		if got, err := f.backend.GlobInfo(f.ctx, &filesystem.GlobInfoRequest{Path: root, Pattern: "**/*.txt"}); err != nil || len(got) != 1 {
			t.Fatalf("readonly glob: %+v %v", got, err)
		}
		if got, err := f.backend.GrepRaw(f.ctx, &filesystem.GrepRequest{Path: root, Pattern: "evidence"}); err != nil || len(got) != 1 {
			t.Fatalf("readonly grep: %+v %v", got, err)
		}
	}
	writeWorkspaceFixture(t, filepath.Join(f.otherReduction, "artifact.txt"), "canary other reduction")
	assertWorkspaceDenied(t, f.backend, f.ctx, filepath.Join(f.otherReduction, "artifact.txt"))
}

func TestWorkspaceFilesystemReadOnlyInsideWorkspace(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	readonly := filepath.Join(f.workspace, "readonly")
	path := filepath.Join(readonly, "evidence.txt")
	writeWorkspaceFixture(t, path, "protected evidence")
	f.policy.ReadOnlyRoots = append(f.policy.ReadOnlyRoots, readonly)
	b := wrapModelFilesystem(f.ctx, nil)
	if got, err := b.Read(f.ctx, &filesystem.ReadRequest{FilePath: path}); err != nil || got.Content != "protected evidence" {
		t.Fatalf("nested readonly read: %+v %v", got, err)
	}
	if err := b.Write(f.ctx, &filesystem.WriteRequest{FilePath: path, Content: "changed"}); err == nil {
		t.Fatal("workspace write overrode nested read-only policy")
	}
	if err := b.Edit(f.ctx, &filesystem.EditRequest{FilePath: path, OldString: "protected", NewString: "changed"}); err == nil {
		t.Fatal("workspace edit overrode nested read-only policy")
	}
}

func TestWorkspaceFilesystemFailClosedAndPolicyIdentity(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	path := filepath.Join(f.workspace, "own.txt")
	writeWorkspaceFixture(t, path, "canary")
	assertWorkspaceDenied(t, wrapModelFilesystem(context.Background(), nil), context.Background(), path)
	assertWorkspaceDenied(t, f.backend, context.Background(), path)
	assertWorkspaceDenied(t, f.backend, workspaceguard.WithPolicy(context.Background(), &workspaceguard.Policy{Workspace: f.workspace}), path)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, err := f.backend.Read(ctx, &filesystem.ReadRequest{FilePath: path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read: %v", err)
	}
	// Changing the source after binding cannot expand an existing backend.
	f.policy.Workspace = f.platform
	f.policy.ReadOnlyRoots[0] = f.platform
	assertWorkspaceDenied(t, f.backend, f.ctx, f.platform)
	if shell, ok := f.backend.(filesystem.Shell); !ok {
		t.Fatal("expected explicit disabled shell")
	} else if _, err := shell.Execute(f.ctx, &filesystem.ExecuteRequest{Command: "echo unsafe"}); err == nil {
		t.Fatal("filesystem shell fallback allowed")
	}
	if _, ok := f.backend.(filesystem.StreamingShell); ok {
		t.Fatal("unrestricted streaming shell leaked from Local")
	}
}

func TestWorkspaceFilesystemConcurrentPolicies(t *testing.T) {
	first, second := newWorkspaceFSFixture(t), newWorkspaceFSFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		for index, f := range []workspaceFSFixture{first, second} {
			wg.Add(1)
			go func(index, i int, f workspaceFSFixture) {
				defer wg.Done()
				name, text := fmt.Sprintf("parallel/%d.txt", i), fmt.Sprintf("policy-%d-%d", index, i)
				if err := f.backend.Write(f.ctx, &filesystem.WriteRequest{FilePath: name, Content: text}); err != nil {
					t.Error(err)
					return
				}
				got, err := f.backend.Read(f.ctx, &filesystem.ReadRequest{FilePath: name})
				if err != nil || got.Content != text {
					t.Errorf("cross-run contamination: %+v %v", got, err)
				}
				other := first
				if index == 0 {
					other = second
				}
				if _, err := f.backend.Read(f.ctx, &filesystem.ReadRequest{FilePath: filepath.Join(other.workspace, name)}); err == nil {
					t.Error("sibling run readable")
				}
			}(index, i, f)
		}
	}
	wg.Wait()
}

func requireWorkspaceSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable on this host: %v", err)
	}
}

func TestWorkspaceFilesystemSymlinksDoNotEscape(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	writeWorkspaceFixture(t, filepath.Join(f.platform, "config.yaml"), "canary outside")
	requireWorkspaceSymlink(t, f.platform, filepath.Join(f.workspace, "escape"))
	requireWorkspaceSymlink(t, filepath.Join(f.platform, "config.yaml"), filepath.Join(f.workspace, "config-link.yaml"))
	for _, path := range []string{"escape", "escape/config.yaml", "config-link.yaml"} {
		assertWorkspaceDenied(t, f.backend, f.ctx, path)
	}
	for _, root := range []string{f.skills, f.reduction} {
		link := filepath.Join(root, "escape")
		requireWorkspaceSymlink(t, f.platform, link)
		assertWorkspaceDenied(t, f.backend, f.ctx, filepath.Join(link, "config.yaml"))
	}
	files, err := f.backend.GlobInfo(f.ctx, &filesystem.GlobInfoRequest{Pattern: "**/*"})
	if err != nil || len(files) != 0 {
		t.Fatalf("glob followed symlink: %+v %v", files, err)
	}
	matches, err := f.backend.GrepRaw(f.ctx, &filesystem.GrepRequest{Pattern: "canary"})
	if err != nil || len(matches) != 0 {
		t.Fatalf("grep followed symlink: %+v %v", matches, err)
	}
	entries, err := f.backend.LsInfo(f.ctx, &filesystem.LsInfoRequest{})
	if err != nil || len(entries) != 0 {
		t.Fatalf("ls returned symlink: %+v %v", entries, err)
	}
}

func TestWorkspaceFilesystemSymlinkSwapRace(t *testing.T) {
	for _, swapRoot := range []bool{false, true} {
		t.Run(fmt.Sprintf("root=%v", swapRoot), func(t *testing.T) {
			f := newWorkspaceFSFixture(t)
			probe := filepath.Join(f.platform, "probe")
			requireWorkspaceSymlink(t, f.platform, probe)
			if err := os.Remove(probe); err != nil {
				t.Fatal(err)
			}
			writeWorkspaceFixture(t, filepath.Join(f.platform, "marker.txt"), "canary must not leak or change")
			writeWorkspaceFixture(t, filepath.Join(f.platform, "outside-only.txt"), "canary")
			flip := filepath.Join(f.workspace, "flip")
			if swapRoot {
				flip = f.workspace
			}
			writeWorkspaceFixture(t, filepath.Join(flip, "marker.txt"), "inside")
			hold := flip + "-held"
			stop, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
					}
					if os.Rename(flip, hold) == nil {
						if os.Symlink(f.platform, flip) == nil {
							runtime.Gosched()
							_ = os.Remove(flip)
						}
						_ = os.Rename(hold, flip)
					}
					runtime.Gosched()
				}
			}()
			defer func() { close(stop); <-done }()
			for i := 0; i < 100; i++ {
				if got, err := f.backend.Read(f.ctx, &filesystem.ReadRequest{FilePath: filepath.Join(flip, "marker.txt")}); err == nil && strings.Contains(got.Content, "canary") {
					t.Fatal("read escaped during rename")
				}
				if got, err := f.backend.GrepRaw(f.ctx, &filesystem.GrepRequest{Path: flip, Pattern: "canary"}); err == nil && len(got) > 0 {
					t.Fatal("grep escaped during rename")
				}
				if got, err := f.backend.GlobInfo(f.ctx, &filesystem.GlobInfoRequest{Path: flip, Pattern: "**/*"}); err == nil {
					for _, item := range got {
						if strings.Contains(item.Path, "outside-only") {
							t.Fatal("glob escaped during rename")
						}
					}
				}
				_ = f.backend.Write(f.ctx, &filesystem.WriteRequest{FilePath: filepath.Join(flip, "marker.txt"), Content: "inside"})
				_ = f.backend.Edit(f.ctx, &filesystem.EditRequest{FilePath: filepath.Join(flip, "marker.txt"), OldString: "inside", NewString: "edited"})
			}
			data, err := os.ReadFile(filepath.Join(f.platform, "marker.txt"))
			if err != nil || string(data) != "canary must not leak or change" {
				t.Fatalf("write escaped during rename: %q %v", data, err)
			}
		})
	}
}
