//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const osInfoTimeout = 10 * time.Second

func getKernelVersion() string {
	// Use RtlGetVersion for accurate Windows version
	mod := syscall.NewLazyDLL("ntdll.dll")
	proc := mod.NewProc("RtlGetVersion")

	type rtlOSVersionInfoEx struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformId        uint32
		szCSDVersion        [128]uint16
	}

	var info rtlOSVersionInfoEx
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))

	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		return ""
	}

	return strings.TrimSpace(strings.Join([]string{
		itoa(int(info.dwMajorVersion)),
		itoa(int(info.dwMinorVersion)),
		itoa(int(info.dwBuildNumber)),
	}, "."))
}

func getDistro() string {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "cmd", "/C", "ver").Output()
	if err != nil {
		return "Windows"
	}

	return strings.TrimSpace(string(out))
}

func getCPUModel() string {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "wmic", "cpu", "get", "Name", "/value").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Name=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Name="))
		}
	}

	return ""
}

// GetMEIDriverVersion returns the Intel MEI driver version on Windows via WMI.
func GetMEIDriverVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like '*Management Engine Interface*' } | Select-Object -First 1 -ExpandProperty DriverVersion").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	result := ""
	for i > 0 {
		result = string(rune('0'+i%10)) + result
		i /= 10
	}

	return result
}

// GetEthernetAdapterCount returns the number of physical ethernet adapters on Windows.
func GetEthernetAdapterCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), osInfoTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		"(Get-NetAdapter -Physical | Where-Object { $_.MediaType -eq '802.3' } | Measure-Object).Count").Output()
	if err != nil {
		return 0
	}

	countStr := strings.TrimSpace(string(out))
	count := 0

	for _, c := range countStr {
		if c >= '0' && c <= '9' {
			count = count*10 + int(c-'0')
		}
	}

	return count
}
