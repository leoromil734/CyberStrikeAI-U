//go:build !unix && !windows

package evidence

import "os"

// Unsupported filesystems/platforms fail closed rather than trust aliases.
func singleLink(file *os.File) bool { return false }
