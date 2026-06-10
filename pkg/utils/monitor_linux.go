/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"os"
	"path/filepath"
	"strings"
)

const monitorConnectedStatus = "connected"

var (
	monitorStatusGlob = func(pattern string) ([]string, error) {
		return filepath.Glob(pattern)
	}
	monitorReadFile = os.ReadFile
)

// DetectMonitorConnected checks if a physical monitor is connected.
// On Linux, reads /sys/class/drm/card*-*/status for "connected".
// Returns nil when detection is not possible (e.g. containers, headless).
func DetectMonitorConnected() *bool {
	return detectMonitor()
}

func detectMonitor() *bool {
	matches, err := monitorStatusGlob("/sys/class/drm/card*-*/status")
	if err != nil || len(matches) == 0 {
		return nil
	}

	readAny := false
	connectedAny := false

	for _, path := range matches {
		data, err := monitorReadFile(path)
		if err != nil {
			continue
		}

		readAny = true

		if strings.TrimSpace(string(data)) == monitorConnectedStatus {
			connectedAny = true
		}
	}

	if !readAny {
		return nil
	}

	connected := connectedAny

	return &connected
}
