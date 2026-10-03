package security

import (
	"context"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/tooloutput"
	"os/exec"
)

func prepareNativeShell(ctx context.Context, cmd *exec.Cmd, command string) (*boundedOutputCollector, *tooloutput.Tee, func(), int, error) {
	runtime, ok := mcp.LocalExecutionRuntimeFromContext(ctx)
	if !ok {
		return nil, nil, func() {}, 0, nil
	}
	release := func() {}
	if runtime.Acquire != nil {
		var err error
		release, err = runtime.Acquire(ctx, "execute", map[string]interface{}{"command": command})
		if err != nil {
			return nil, nil, func() {}, 0, err
		}
	}
	executor := &Executor{spillRootDir: runtime.SpillRoot}
	if err := executor.applyExecutionArtifactEnv(ctx, cmd); err != nil {
		release()
		return nil, nil, func() {}, 0, err
	}
	if runtime.MaxOutputBytes <= 0 {
		return nil, nil, release, 0, nil
	}
	tee := tooloutput.NewTee(executor.spillOptsFromContext(ctx))
	return newBoundedOutputCollector(runtime.MaxOutputBytes/2, tee), tee, release, runtime.MaxOutputBytes, nil
}
func finishNativeOriginal(written *boundedOutputCollector, tee *tooloutput.Tee, budget int) string {
	if written == nil || tee == nil {
		return ""
	}
	_ = tee.Close()
	if !written.truncated {
		return ""
	}
	if path := tee.Path(); path != "" {
		return "\n" + tooloutput.FormatPersistedFromFile(path, written.seenBytes, budget-written.builder.Len()-1)
	}
	return "\n[原件落盘失败；输出仅为部分预览，不能宣称完整]"
}
