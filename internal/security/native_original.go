package security

import (
	"context"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/tooloutput"
	"io"
	"sync"
)

type nativeOriginalWriter struct {
	ctx context.Context
	tee *tooloutput.Tee
}

func (w nativeOriginalWriter) Write(p []byte) (int, error) {
	mcp.NotifyLocalExecutionActivity(w.ctx)
	if w.tee != nil {
		return w.tee.Write(p)
	}
	return len(p), nil
}
func drainShellPipesOriginal(ctx context.Context, stdout, stderr io.Reader, tee *tooloutput.Tee) {
	writer := nativeOriginalWriter{ctx: ctx, tee: tee}
	var wg sync.WaitGroup
	wg.Add(2)
	for _, reader := range []io.Reader{stdout, stderr} {
		go func(reader io.Reader) { defer wg.Done(); _, _ = io.Copy(writer, reader) }(reader)
	}
	wg.Wait()
}
