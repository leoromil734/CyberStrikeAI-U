//go:build windows

package workspaceguard

import (
	"os"
	"syscall"
)

// SingleLink checks the handle instead of following the file name a second time.
func SingleLink(file *os.File) bool {
	if file == nil {
		return false
	}
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info) != nil {
		return false
	}
	return info.NumberOfLinks == 1
}
