/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
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

	info.Version = getKernelVersion()
	info.Distro = getDistro()

	return info
}

// GetCPUModel returns the CPU model name from /proc/cpuinfo (Linux) or a fallback.
func GetCPUModel() string {
	return getCPUModel()
}

// GetOSIPAddress returns the primary non-loopback IPv4 address.
func GetOSIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		if ip.IsLoopback() || ip.To4() == nil {
			continue
		}

		return ip.String()
	}

	return ""
}

// readOSRelease reads /etc/os-release and returns a key-value map.
func readOSRelease() map[string]string {
	result := make(map[string]string)

	f, err := os.Open("/etc/os-release")
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := strings.Trim(parts[1], "\"")
		result[key] = value
	}

	return result
}
