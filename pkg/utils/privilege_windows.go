//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errElevationDeclined is returned when the user dismisses the UAC prompt.
var errElevationDeclined = errors.New("elevation was declined at the UAC prompt")

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
	escaped := []string{escapeCmdMetachars(syscall.EscapeArg(exe))}
	for _, arg := range os.Args[1:] {
		escaped = append(escaped, escapeCmdMetachars(syscall.EscapeArg(arg)))
	}

	// /s makes cmd.exe strip exactly the outer quote pair we add here. Without
	// it, cmd strips the first and last quote on the line, splitting any quoted
	// path apart into "The system cannot find the path specified."
	cmdLine := fmt.Sprintf(`/s /c "%s & echo. & echo Press any key to exit... & pause >nul"`, strings.Join(escaped, " "))

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
		//nolint:misspell // because: ERROR_CANCELLED is the Win32 constant name in x/sys/windows
		if errors.Is(sysErr, windows.ERROR_CANCELLED) {
			return errElevationDeclined
		}

		return fmt.Errorf("ShellExecuteEx failed: %w", sysErr)
	}

	if sei.hProcess == 0 {
		return nil
	}

	defer windows.CloseHandle(windows.Handle(sei.hProcess))

	// Block until the elevated process exits, so we outlive the UAC prompt.
	// `go run` deletes our executable as soon as we return, leaving the child
	// with "The system cannot find the path specified."
	if _, err := windows.WaitForSingleObject(windows.Handle(sei.hProcess), windows.INFINITE); err != nil {
		return fmt.Errorf("failed to wait for elevated process: %w", err)
	}

	return nil
}

// cmdMetachars are the characters cmd.exe interprets outside a quoted region.
const cmdMetachars = `^&|<>()`

// escapeCmdMetachars escapes cmd.exe metacharacters with ^, skipping quoted
// regions where cmd already treats them literally and ^ is not an escape
// character (escaping there would leak a caret into the argument).
func escapeCmdMetachars(s string) string {
	var (
		b        strings.Builder
		inQuotes bool
	)

	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case !inQuotes && strings.ContainsRune(cmdMetachars, r):
			b.WriteRune('^')
		}

		b.WriteRune(r)
	}

	return b.String()
}
