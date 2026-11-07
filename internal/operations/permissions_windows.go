//go:build windows

package operations

import (
	"golang.org/x/sys/windows"
	"strings"
)

// Protect backup/restore trees even when their parent inherits broad read ACLs.
func secureDirectory(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(nativeWindowsPath(path), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func nativeWindowsPath(path string) string {
	if strings.HasPrefix(path, `\\?\`) {
		return path
	}
	if strings.HasPrefix(path, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
	}
	return `\\?\` + path
}
func publishDirectory(from, to string) error {
	source, err := windows.UTF16PtrFromString(nativeWindowsPath(from))
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(nativeWindowsPath(to))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, target, windows.MOVEFILE_WRITE_THROUGH)
}
