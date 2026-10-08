//go:build !unix && !windows

package workspaceguard

import "os"

// Unknown platforms fail closed rather than assume there are no hard links.
func SingleLink(file *os.File) bool { return false }
