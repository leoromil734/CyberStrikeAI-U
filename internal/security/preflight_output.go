package security

import (
	"context"
	"os/exec"
	"strings"
	"sync"
)

type helpOutput struct {
	mu   sync.Mutex
	text strings.Builder
}

func (h *helpOutput) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := 16000 - h.text.Len()
	if room > len(p) {
		room = len(p)
	}
	if room > 0 {
		h.text.Write(p[:room])
	}
	return len(p), nil
}
func boundedHelpOutput(ctx context.Context, cmd *exec.Cmd) (string, error) {
	output := &helpOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	session, err := StartShellSession(cmd)
	if err != nil {
		return "", err
	}
	finished := make(chan error, 1)
	go func() { finished <- session.Wait() }()
	select {
	case err = <-finished:
	case <-ctx.Done():
		TerminateShellCmdSession(session)
		<-finished
		err = ctx.Err()
	}
	output.mu.Lock()
	defer output.mu.Unlock()
	return strings.ToValidUTF8(output.text.String(), ""), err
}
