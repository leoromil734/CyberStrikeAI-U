//go:build !linux

package security

import (
	"cyberstrike-ai/internal/workspaceguard"
	"fmt"
	"os/exec"
)

func workspaceIdentity(*workspaceguard.Policy, *exec.Cmd) ([]string, error) {
	return nil, fmt.Errorf("isolated local execution requires Linux")
}
