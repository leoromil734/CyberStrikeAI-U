package multiagent

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk/filesystem"
)

func TestWorkspaceHidesLegacySharedSkillTaskState(t *testing.T) {
	f := newWorkspaceFSFixture(t)
	private := filepath.Join(f.skills, ".eino")
	f.policy.DeniedRoots = []string{private}
	f.backend = wrapModelFilesystem(f.ctx, nil)
	writeWorkspaceFixture(t, filepath.Join(private, "other-conversation", "task.json"), "private-canary")
	writeWorkspaceFixture(t, filepath.Join(f.skills, "fixture", "SKILL.md"), "public-skill")
	assertWorkspaceDenied(t, f.backend, f.ctx, filepath.Join(private, "other-conversation", "task.json"))
	matches, err := f.backend.GrepRaw(f.ctx, &filesystem.GrepRequest{Path: f.skills, Pattern: "canary"})
	if err != nil || len(matches) != 0 {
		t.Fatalf("private task state appeared in grep: %v %+v", err, matches)
	}
	files, err := f.backend.GlobInfo(f.ctx, &filesystem.GlobInfoRequest{Path: f.skills, Pattern: "**/*"})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.Contains(file.Path, ".eino") {
			t.Fatal("private state appeared in glob")
		}
	}
	files, err = f.backend.LsInfo(f.ctx, &filesystem.LsInfoRequest{Path: f.skills})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.Contains(file.Path, ".eino") {
			t.Fatal("private state appeared in ls")
		}
	}
}
