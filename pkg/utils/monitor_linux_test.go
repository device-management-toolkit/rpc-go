//go:build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"errors"
	"testing"
)

func restoreMonitorSeams(t *testing.T) {
	origGlob := monitorStatusGlob
	origRead := monitorReadFile

	t.Cleanup(func() {
		monitorStatusGlob = origGlob
		monitorReadFile = origRead
	})
}

func TestDetectMonitorConnected(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		read  func(string) ([]byte, error)
		want  *bool
	}{
		{
			name:  "multi monitor any connected",
			paths: []string{"/sys/class/drm/card0-DP-1/status", "/sys/class/drm/card0-HDMI-A-1/status"},
			read: func(path string) ([]byte, error) {
				switch path {
				case "/sys/class/drm/card0-DP-1/status":
					return []byte("disconnected\n"), nil
				case "/sys/class/drm/card0-HDMI-A-1/status":
					return []byte("connected\n"), nil
				default:
					return nil, errors.New("unexpected path")
				}
			},
			want: boolPtr(true),
		},
		{
			name:  "all disconnected",
			paths: []string{"/sys/class/drm/card0-DP-1/status", "/sys/class/drm/card0-HDMI-A-1/status"},
			read:  func(string) ([]byte, error) { return []byte("disconnected\n"), nil },
			want:  boolPtr(false),
		},
		{
			name:  "no readable status",
			paths: []string{"/sys/class/drm/card0-DP-1/status"},
			read:  func(string) ([]byte, error) { return nil, errors.New("read failed") },
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreMonitorSeams(t)

			monitorStatusGlob = func(string) ([]string, error) { return tt.paths, nil }
			monitorReadFile = tt.read

			got := DetectMonitorConnected()

			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("DetectMonitorConnected() = %v, want nil", got)
			case tt.want != nil && (got == nil || *got != *tt.want):
				t.Fatalf("DetectMonitorConnected() = %v, want %v", got, *tt.want)
			}
		})
	}
}

func boolPtr(v bool) *bool {
	return &v
}
