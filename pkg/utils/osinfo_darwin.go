/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const (
	networksetupTimeout = 2 * time.Second
	hardwarePortPrefix  = "Hardware Port:"
	devicePrefix        = "Device:"
)

var runNetworksetup = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "networksetup", args...).Output()
}

// GetMEIDriverVersion returns empty on macOS, which has no MEI driver.
func GetMEIDriverVersion() string {
	return ""
}

// isWirelessInterface also checks the hardware port, since macOS names Wi-Fi like Ethernet (en0).
func isWirelessInterface(name string) bool {
	if isWirelessAdapter(name) {
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), networksetupTimeout)
	defer cancel()

	out, err := runNetworksetup(ctx, "-listallhardwareports")
	if err != nil {
		return false
	}

	return isWirelessAdapter(hardwarePortForDevice(string(out), name))
}

// hardwarePortForDevice returns the hardware port label networksetup lists for device.
func hardwarePortForDevice(output, device string) string {
	port := ""

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if value, ok := strings.CutPrefix(line, hardwarePortPrefix); ok {
			port = strings.TrimSpace(value)

			continue
		}

		if value, ok := strings.CutPrefix(line, devicePrefix); ok && strings.TrimSpace(value) == device {
			return port
		}
	}

	return ""
}

func getAdapterDHCPEnabled(string) *bool {
	return nil
}

func getAdapterDisplayName(string) string {
	return ""
}
