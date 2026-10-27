//go:build windows

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const windowsCurrentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

func getPlatformOSInfo() OSInfo {
	info := OSInfo{}

	v := windows.RtlGetVersion()
	build := v.BuildNumber

	var productName, displayVersion string

	var ubr uint64

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsCurrentVersionKey, registry.QUERY_VALUE); err == nil {
		productName, _, _ = k.GetStringValue("ProductName")
		displayVersion, _, _ = k.GetStringValue("DisplayVersion")
		ubr, _, _ = k.GetIntegerValue("UBR")
		k.Close()
	}

	info.Version = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, build)
	if ubr != 0 {
		info.Version = fmt.Sprintf("%s.%d", info.Version, ubr)
	}

	info.Distro = windowsDistro(productName, displayVersion, build)

	return info
}

// windowsDistro builds a friendly product string. The registry ProductName
// still reads "Windows 10 ..." on Windows 11, so it is corrected by build number.
func windowsDistro(productName, displayVersion string, build uint32) string {
	const firstWindows11Build = 22000

	productName = strings.TrimSpace(productName)
	if build >= firstWindows11Build && strings.HasPrefix(productName, "Windows 10") {
		productName = "Windows 11" + strings.TrimPrefix(productName, "Windows 10")
	}

	return strings.TrimSpace(productName + " " + strings.TrimSpace(displayVersion))
}
