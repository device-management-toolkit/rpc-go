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

func TestGetMEIDriverVersion(t *testing.T) {
	originalRunModinfo := runModinfo
	originalGetKernelRelease := getKernelRelease

	t.Cleanup(func() {
		runModinfo = originalRunModinfo
		getKernelRelease = originalGetKernelRelease
	})

	tests := []struct {
		name              string
		runModinfoMock    func(context.Context, ...string) ([]byte, error)
		kernelReleaseMock string
		want              string
	}{
		{
			name: "prefers modinfo version",
			runModinfoMock: func(_ context.Context, args ...string) ([]byte, error) {
				if len(args) >= 3 && args[0] == "-F" && args[1] == "version" && args[2] == "mei_me" {
					return []byte("5.15.94-lts-230320t134421z\n"), nil
				}

				return nil, errors.New("unexpected call")
			},
			kernelReleaseMock: "6.8.0-94-generic",
			want:              "5.15.94-lts-230320t134421z",
		},
		{
			name: "falls back to module path",
			runModinfoMock: func(_ context.Context, args ...string) ([]byte, error) {
				if len(args) >= 3 && args[0] == "-F" && args[1] == "version" && args[2] == "mei_me" {
					return []byte("\n"), nil
				}

				if len(args) >= 2 && args[0] == "-n" && args[1] == "mei_me" {
					return []byte("/lib/modules/6.8.0-94-generic/kernel/drivers/misc/mei/mei-me.ko\n"), nil
				}

				return nil, errors.New("unexpected call")
			},
			kernelReleaseMock: "6.8.0-94-generic",
			want:              "6.8.0-94-generic",
		},
		{
			name: "falls back to kernel release",
			runModinfoMock: func(_ context.Context, args ...string) ([]byte, error) {
				if len(args) >= 3 && args[0] == "-F" && args[1] == "version" && args[2] == "mei_me" {
					return nil, errors.New("modinfo version failed")
				}

				if len(args) >= 2 && args[0] == "-n" && args[1] == "mei_me" {
					return nil, errors.New("modinfo path failed")
				}

				return nil, errors.New("unexpected call")
			},
			kernelReleaseMock: "6.8.0-94-generic",
			want:              "6.8.0-94-generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runModinfo = tt.runModinfoMock
			getKernelRelease = func() string { return tt.kernelReleaseMock }

			if got := GetMEIDriverVersion(); got != tt.want {
				t.Fatalf("GetMEIDriverVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseMEIModuleVersionFromPath(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		want       string
		wantOK     bool
	}{
		{
			name:       "in-tree ubuntu 24.04 module path",
			modulePath: "/lib/modules/6.17.0-35-generic/kernel/drivers/misc/mei/mei-me.ko.zst",
			want:       "6.17.0-35-generic",
			wantOK:     true,
		},
		{
			name:       "in-tree ubuntu 22.04 module path",
			modulePath: "/lib/modules/5.15.0-164-generic/kernel/drivers/misc/mei/mei-me.ko",
			want:       "5.15.0-164-generic",
			wantOK:     true,
		},
		{
			name:       "updates path gets updates suffix",
			modulePath: "/lib/modules/6.17.0-35-generic/updates/mei-me.ko",
			want:       "6.17.0-35-generic-updates",
			wantOK:     true,
		},
		{
			name:       "updates dkms path gets updates suffix",
			modulePath: "/lib/modules/6.17.0-35-generic/updates/dkms/mei-me.ko",
			want:       "6.17.0-35-generic-updates",
			wantOK:     true,
		},
		{
			name:       "extra path gets extra suffix",
			modulePath: "/lib/modules/6.17.0-35-generic/extra/mei-me.ko",
			want:       "6.17.0-35-generic-extra",
			wantOK:     true,
		},
		{
			name:       "invalid path returns false",
			modulePath: "/tmp/mei-me.ko",
			want:       "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseMEIModuleVersionFromPath(tt.modulePath)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}

			if got != tt.want {
				t.Fatalf("version = %q, want %q", got, tt.want)
			}
		})
	}
}
