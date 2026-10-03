//go:build windows

package evidence

import (
	"os"
	"syscall"
)

// Reject hard-link aliases, which otherwise bypass a directory-only boundary.
func singleLink(file *os.File) bool {
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info) != nil {
		return false
	}
	return info.NumberOfLinks == 1
}
