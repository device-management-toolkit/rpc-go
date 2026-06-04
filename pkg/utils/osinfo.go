/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"bufio"
	"os"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	gnet "github.com/shirou/gopsutil/v4/net"
)

// OSInfo holds operating system metadata.
type OSInfo struct {
	Name    string
	Version string
	Distro  string
}

// GetOSInfo returns the OS name, kernel/build version, and distro string.
func GetOSInfo() OSInfo {
	info := OSInfo{
		Name: runtime.GOOS,
	}

	hostInfo, err := host.Info()
	if err != nil {
		return info
	}

	info.Version = strings.TrimSpace(hostInfo.KernelVersion)

	switch runtime.GOOS {
	case "linux":
		// Use PRETTY_NAME from /etc/os-release for full distro string (e.g. "Ubuntu 22.04.5 LTS")
		if prettyName := readPrettyName(); prettyName != "" {
			info.Distro = prettyName
		} else {
			info.Distro = strings.TrimSpace(hostInfo.Platform + " " + hostInfo.PlatformVersion)
		}
	case "windows":
		// Combine platform + version for friendly name (e.g. "Microsoft Windows 11 Enterprise 24H2")
		info.Distro = strings.TrimSpace(hostInfo.Platform + " " + hostInfo.PlatformVersion)
	default:
		info.Distro = strings.TrimSpace(hostInfo.Platform)
	}

	return info
}

// readPrettyName reads PRETTY_NAME from /etc/os-release.
func readPrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	return ""
}

// GetCPUModel returns the CPU model name.
func GetCPUModel() string {
	cpuInfo, err := cpu.Info()
	if err != nil || len(cpuInfo) == 0 {
		return ""
	}

	return strings.TrimSpace(cpuInfo[0].ModelName)
}

// GetOSIPAddress returns the primary non-loopback IPv4 address.
func GetOSIPAddress() string {
	ifaces, err := gnet.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if strings.Contains(strings.ToLower(iface.Name), "lo") {
			continue
		}

		for _, addr := range iface.Addrs {
			ip := strings.SplitN(addr.Addr, "/", 2)[0]
			if ip != "" && !strings.Contains(ip, ":") {
				return ip
			}
		}
	}

	return ""
}

// GetEthernetAdapterCount returns the number of physical ethernet adapters.
func GetEthernetAdapterCount() int {
	ifaces, err := gnet.Interfaces()
	if err != nil {
		return 0
	}

	count := 0

	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "lo") || iface.HardwareAddr == "" {
			continue
		}

		if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") {
			count++
		}
	}

	return count
}
