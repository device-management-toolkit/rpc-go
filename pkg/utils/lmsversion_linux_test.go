//go:build linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"errors"
	"testing"
)

func TestGetLMSVersion(t *testing.T) {
	originalLookPath := lmsLookPath
	originalCommandOutput := lmsCommandOutput
	originalGetOSInfo := lmsGetOSInfo

	t.Cleanup(func() {
		lmsLookPath = originalLookPath
		lmsCommandOutput = originalCommandOutput
		lmsGetOSInfo = originalGetOSInfo
	})

	tests := []struct {
		name            string
		distro          string
		lookPath        func(string) (string, error)
		command         func(context.Context, string, ...string) ([]byte, error)
		want            string
		wantDPKGInvoked bool
		wantRPMInvoked  bool
	}{
		{
			name:   "ubuntu no package does not fallback to rpm",
			distro: "Ubuntu 22.04.5 LTS",
			lookPath: func(file string) (string, error) {
				switch file {
				case "dpkg-query":
					return "/usr/bin/dpkg-query", nil
				case "rpm":
					return "/usr/bin/rpm", nil
				default:
					return "", errors.New("not found")
				}
			},
			command: func(_ context.Context, name string, _ ...string) ([]byte, error) {
				switch name {
				case "dpkg-query":
					return nil, errors.New("package lms is not installed")
				case "snap":
					return nil, errors.New("snap not available")
				default:
					return nil, errors.New("unexpected command")
				}
			},
			want:            "",
			wantDPKGInvoked: true,
			wantRPMInvoked:  false,
		},
		{
			name:   "fedora uses rpm",
			distro: "Fedora Linux",
			lookPath: func(file string) (string, error) {
				if file == "rpm" {
					return "/usr/bin/rpm", nil
				}

				return "", errors.New("not found")
			},

			command: func(_ context.Context, name string, _ ...string) ([]byte, error) {
				if name == "rpm" {
					return []byte("2406.0.0.0"), nil
				}

				return nil, errors.New("unexpected command")
			},
			want:           "2406.0.0.0",
			wantRPMInvoked: true,
		},
		{
			name:   "unknown distro uses snap first",
			distro: "Custom Linux",
			lookPath: func(file string) (string, error) {
				switch file {
				case "dpkg-query":
					return "/usr/bin/dpkg-query", nil
				case "rpm":
					return "/usr/bin/rpm", nil
				default:
					return "", errors.New("not found")
				}
			},
			command: func(_ context.Context, name string, _ ...string) ([]byte, error) {
				switch name {
				case "snap":
					return []byte("Name  Version  Rev  Tracking\nlms   2406.0.0.0  10  latest/stable\n"), nil
				case "dpkg-query", "rpm":
					return nil, errors.New("should not be called when snap succeeds")
				default:
					return nil, errors.New("unexpected command")
				}
			},
			want:            "2406.0.0.0",
			wantDPKGInvoked: false,
			wantRPMInvoked:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpmInvoked := false
			dpkgInvoked := false

			lmsGetOSInfo = func() OSInfo { return OSInfo{Distro: tt.distro} }
			lmsLookPath = tt.lookPath

			lmsCommandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "dpkg-query" {
					dpkgInvoked = true
				}

				if name == "rpm" {
					rpmInvoked = true
				}

				return tt.command(ctx, name, args...)
			}

			if got := GetLMSVersion(); got != tt.want {
				t.Fatalf("GetLMSVersion() = %q, want %q", got, tt.want)
			}

			if dpkgInvoked != tt.wantDPKGInvoked {
				t.Fatalf("dpkg invoked = %v, want %v", dpkgInvoked, tt.wantDPKGInvoked)
			}

			if rpmInvoked != tt.wantRPMInvoked {
				t.Fatalf("rpm invoked = %v, want %v", rpmInvoked, tt.wantRPMInvoked)
			}
		})
	}
}
