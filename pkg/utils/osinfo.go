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
	case goosWindows:
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
// It prefers physical ethernet adapters, skips link-local (169.254.x.x),
// and skips virtual adapters (Hyper-V, WSL, Docker, VPN, etc.).
func GetOSIPAddress() string {
	ifaces, err := gnet.Interfaces()
	if err != nil {
		return ""
	}

	var fallback string

	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if name == "lo" || strings.Contains(name, "loopback") {
			continue
		}

		// Skip virtual/software adapters
		if isVirtualAdapter(name) {
			continue
		}

		for _, addr := range iface.Addrs {
			ip := strings.SplitN(addr.Addr, "/", 2)[0]
			if ip == "" || strings.Contains(ip, ":") {
				continue
			}

			// Skip link-local (APIPA) addresses
			if strings.HasPrefix(ip, "169.254.") {
				continue
			}

			// Prefer physical ethernet interfaces
			if isPhysicalEthernet(name) {
				return ip
			}

			// Store first valid non-link-local as fallback
			if fallback == "" {
				fallback = ip
			}
		}
	}

	return fallback
}

// isVirtualAdapter returns true for known virtual/software adapter names.
func isVirtualAdapter(name string) bool {
	virtualPrefixes := []string{
		"vethernet", // Hyper-V / WSL
		"vmnet",     // VMware
		"vboxnet",   // VirtualBox
		"docker",    // Docker
		"br-",       // Docker bridge
		"veth",      // Container veth pairs
		"virbr",     // libvirt
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) || strings.Contains(name, prefix) {
			return true
		}
	}

	return false
}

// isPhysicalEthernet returns true for likely physical ethernet interface names.
func isPhysicalEthernet(name string) bool {
	// Linux: eth0, eno1, ens3, enp0s3
	// Windows: "ethernet", "ethernet 2"
	return strings.HasPrefix(name, "eth") ||
		strings.HasPrefix(name, "en") ||
		name == "ethernet" ||
		strings.HasPrefix(name, "ethernet ")
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
		if name == "lo" || strings.Contains(name, "loopback") || iface.HardwareAddr == "" {
			continue
		}

		if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") {
			count++
		}
	}

	return count
}
