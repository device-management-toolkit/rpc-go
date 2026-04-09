//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CanAMTBeSupported reports whether the current OS can have MEI/HECI hardware.
// Returns true on Windows where vPro systems exist, but does not guarantee
// the hardware is actually present — HECI calls determine that at runtime.
func CanAMTBeSupported() bool {
	return true
}

// IsElevated returns true if the current process has administrator privileges.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// shellExecuteInfo mirrors the Win32 SHELLEXECUTEINFOW structure.
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

// SelfElevate re-launches the current process with administrator privileges via UAC.
// On success, the elevated process runs in a new console window. The current process
// should exit after calling this.
func SelfElevate() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}

	// Use the system cmd.exe via %SystemRoot% (not COMSPEC which is user-controlled).
	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")

	file, err := windows.UTF16PtrFromString(cmdExe)
	if err != nil {
		return err
	}

	// Escape each argument for both argv parsing and cmd.exe metacharacters,
	// then append "& pause" to keep the elevated console window open.
	var escaped []string
	for _, arg := range os.Args[1:] {
		escaped = append(escaped, escapeCmdMetachars(syscall.EscapeArg(arg)))
	}

	cmdLine := fmt.Sprintf(`/c %s %s & echo. & echo Press any key to exit... & pause >nul`, escapeCmdMetachars(syscall.EscapeArg(exe)), strings.Join(escaped, " "))

	params, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return err
	}

	const (
		seeMaskNoCloseProcess = 0x00000040
		swShowNormal          = 1
	)

	sei := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        swShowNormal,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))

	shell32 := windows.NewLazyDLL("shell32.dll")
	shellExecuteEx := shell32.NewProc("ShellExecuteExW")

	r, _, sysErr := shellExecuteEx.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		return fmt.Errorf("ShellExecuteEx failed: %w", sysErr)
	}

	if sei.hProcess != 0 {
		windows.CloseHandle(windows.Handle(sei.hProcess))
	}

	return nil
}

// escapeCmdMetachars escapes cmd.exe metacharacters with ^ to prevent interpretation.
func escapeCmdMetachars(s string) string {
	r := strings.NewReplacer(
		"^", "^^", "&", "^&", "|", "^|",
		"<", "^<", ">", "^>",
	)

	return r.Replace(s)
}
