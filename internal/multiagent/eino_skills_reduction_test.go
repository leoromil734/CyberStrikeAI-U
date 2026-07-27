package multiagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"

	localbk "github.com/cloudwego/eino-ext/adk/backend/local"
	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
)

func TestPrepareEinoSkillsStillCreatesReductionBackendWhenSkillsDisabled(t *testing.T) {
	ma := &config.MultiAgentConfig{
		EinoSkills: config.MultiAgentEinoSkillsConfig{Disable: true},
		EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{
			ReductionEnable: true,
		},
	}
	loc, skillMW, fsTools, skillsRoot, err := prepareEinoSkills(context.Background(), "", ma, nil)
	if err != nil {
		t.Fatal(err)
	}
	if loc == nil {
		t.Fatal("reduction backend must exist even when Skills are disabled")
	}
	if skillMW != nil || fsTools || skillsRoot != "" {
		t.Fatalf("Skills unexpectedly enabled: mw=%v fs=%v root=%q", skillMW, fsTools, skillsRoot)
	}
}

func TestPrepareEinoSkillsDoesNotCreateBackendWhenReductionDisabled(t *testing.T) {
	ma := &config.MultiAgentConfig{
		EinoSkills: config.MultiAgentEinoSkillsConfig{Disable: true},
	}
	loc, skillMW, fsTools, skillsRoot, err := prepareEinoSkills(context.Background(), "", ma, nil)
	if err != nil {
		t.Fatal(err)
	}
	if loc != nil || skillMW != nil || fsTools || skillsRoot != "" {
		t.Fatalf("filesystem unexpectedly mounted: loc=%v mw=%v fs=%v root=%q", loc, skillMW, fsTools, skillsRoot)
	}
}

func TestNeedsReductionReadFileMiddleware(t *testing.T) {
	loc := &localbk.Local{}
	tests := []struct {
		name                  string
		reductionEnabled      bool
		fullFilesystemMounted bool
		loc                   *localbk.Local
		want                  bool
	}{
		{name: "reduction only", reductionEnabled: true, loc: loc, want: true},
		{name: "full filesystem avoids duplicate", reductionEnabled: true, fullFilesystemMounted: true, loc: loc},
		{name: "reduction disabled", loc: loc},
		{name: "backend unavailable", reductionEnabled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsReductionReadFileMiddleware(tt.reductionEnabled, tt.fullFilesystemMounted, tt.loc); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReductionReadFileMiddlewareExposesOnlyReadFile(t *testing.T) {
	ctx := context.Background()
	loc, err := localbk.NewBackend(ctx, &localbk.Config{})
	if err != nil {
		t.Fatal(err)
	}
	mw, err := reductionReadFileMiddleware(ctx, loc)
	if err != nil {
		t.Fatal(err)
	}
	_, runCtx, err := mw.BeforeAgent(ctx, &adk.ChatModelAgentContext{Instruction: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if len(runCtx.Tools) != 1 {
		t.Fatalf("expected only read_file, got %d tools", len(runCtx.Tools))
	}
	info, err := runCtx.Tools[0].Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "read_file" {
		t.Fatalf("expected read_file, got %q", info.Name)
	}
	if !strings.Contains(runCtx.Instruction, "<persisted-output>") || !strings.Contains(runCtx.Instruction, "不要用 exec/execute") {
		t.Fatalf("missing reduction read guidance: %q", runCtx.Instruction)
	}

	path := filepath.Join(t.TempDir(), "tooluse_test")
	const persisted = "persisted result\nsecond line"
	if err := os.WriteFile(path, []byte(persisted), 0o600); err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal(map[string]any{"file_path": path})
	if err != nil {
		t.Fatal(err)
	}
	readTool, ok := runCtx.Tools[0].(tool.InvokableTool)
	if !ok {
		t.Fatal("read_file is not invokable")
	}
	got, err := readTool.InvokableRun(ctx, string(args))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "persisted result") || !strings.Contains(got, "second line") {
		t.Fatalf("unexpected read_file output: %q", got)
	}
}
