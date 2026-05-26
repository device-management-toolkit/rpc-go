/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"bufio"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func getKernelVersion() string {
	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return ""
	}

	return strings.TrimRight(string(uname.Release[:]), "\x00")
}

func getDistro() string {
	rel := readOSRelease()
	if name, ok := rel["PRETTY_NAME"]; ok {
		return name
	}

	return ""
}

// GetMEIDriverVersion returns the MEI kernel module version.
// On Linux, MEI is an in-tree module so its version is the kernel version.
func GetMEIDriverVersion() string {
	return getKernelVersion()
}

func getCPUModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// GetEthernetAdapterCount returns the number of physical ethernet adapters on Linux.
func GetEthernetAdapterCount() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}

	count := 0

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if len(iface.HardwareAddr) == 0 {
			continue
		}

		name := iface.Name
		if strings.HasPrefix(name, "eth") ||
			strings.HasPrefix(name, "en") ||
			strings.HasPrefix(name, "eno") ||
			strings.HasPrefix(name, "ens") ||
			strings.HasPrefix(name, "enp") {
			count++
		}
	}

	return count
}
