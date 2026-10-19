/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func restoreLinuxAdapterNameSeams(t *testing.T) {
	originalReadDevicePath := readAdapterDevicePath
	originalResolveExecutable := resolveLspciExecutable
	originalRunLspci := runLspciCommand

	t.Cleanup(func() {
		readAdapterDevicePath = originalReadDevicePath
		resolveLspciExecutable = originalResolveExecutable
		runLspciCommand = originalRunLspci
	})
}

func TestGetAdapterDisplayNameMissingLspci(t *testing.T) {
	restoreLinuxAdapterNameSeams(t)

	readAdapterDevicePath = func(string) (string, error) { return "/sys/devices/pci0000:00/0000:00:02.0", nil }
	resolveLspciExecutable = func(string) string { return "" }
	runLspciCommand = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("lspci must not run when it is unavailable")

		return nil, nil
	}

	if got := getAdapterDisplayName("enp0s2"); got != "" {
		t.Fatalf("getAdapterDisplayName() = %q, want empty", got)
	}
}

func TestGetAdapterDisplayNameEmptyLspciOutput(t *testing.T) {
	restoreLinuxAdapterNameSeams(t)

	readAdapterDevicePath = func(string) (string, error) { return "/sys/devices/pci0000:00/0000:00:02.0", nil }

	resolveLspciExecutable = func(string) string { return "/usr/bin/lspci" }
	runLspciCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }

	if got := getAdapterDisplayName("enp0s2"); got != "" {
		t.Fatalf("getAdapterDisplayName() = %q, want empty", got)
	}
}

func TestGetAdapterDisplayNameSuccess(t *testing.T) {
	restoreLinuxAdapterNameSeams(t)

	const devicePath = "/sys/devices/pci0000:00/0000:00:02.0"

	readAdapterDevicePath = func(path string) (string, error) {
		if path != "/sys/class/net/enp0s2/device" {
			t.Fatalf("readAdapterDevicePath() path = %q", path)
		}

		return devicePath, nil
	}
	resolveLspciExecutable = func(name string) string {
		if name != "lspci" {
			t.Fatalf("resolveLspciExecutable() name = %q, want lspci", name)
		}

		return "/usr/bin/lspci"
	}
	runLspciCommand = func(_ context.Context, executable string, args ...string) ([]byte, error) {
		if executable != "/usr/bin/lspci" {
			t.Fatalf("lspci executable = %q, want /usr/bin/lspci", executable)
		}

		if len(args) != 3 || args[0] != "-D" || args[1] != "-s" || args[2] != filepath.Base(devicePath) {
			t.Fatalf("lspci args = %q, want [-D -s %s]", args, filepath.Base(devicePath))
		}

		return []byte("0000:00:02.0 Ethernet controller: Intel Corporation Ethernet Controller\n"), nil
	}

	if got, want := getAdapterDisplayName("enp0s2"), "Ethernet controller: Intel Corporation Ethernet Controller"; got != want {
		t.Fatalf("getAdapterDisplayName() = %q, want %q", got, want)
	}
}

func TestFindLinuxSystemExecutableIgnoresPath(t *testing.T) {
	attackerDirectory := t.TempDir()

	plantedExecutable := filepath.Join(attackerDirectory, "lspci")

	if err := os.WriteFile(plantedExecutable, []byte("not executable"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", attackerDirectory)

	if got := findLinuxSystemExecutable("lspci"); got == plantedExecutable {
		t.Fatalf("trusted executable lookup selected caller-controlled path %q", got)
	}
}

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
