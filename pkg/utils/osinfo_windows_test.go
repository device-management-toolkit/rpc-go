//go:build windows

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
	"strings"
	"testing"
)

func restoreWindowsOSInfoSeams(t *testing.T) {
	originalLookupExecutable := lookupExecutable
	originalGetAdapterSystemDirectory := getAdapterSystemDirectory
	originalRunCommandOutput := runCommandOutput

	t.Cleanup(func() {
		lookupExecutable = originalLookupExecutable
		getAdapterSystemDirectory = originalGetAdapterSystemDirectory
		runCommandOutput = originalRunCommandOutput
	})
}

func makeTestPowerShell(t *testing.T, systemDirectory string) string {
	t.Helper()

	path := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestGetAdapterDisplayNameMissingPowerShell(t *testing.T) {
	restoreWindowsOSInfoSeams(t)

	getAdapterSystemDirectory = func() (string, error) { return t.TempDir(), nil }
	runCommandOutput = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("PowerShell must not run when it is unavailable")

		return nil, nil
	}

	if got := getAdapterDisplayName("Ethernet"); got != "" {
		t.Fatalf("getAdapterDisplayName() = %q, want empty", got)
	}
}

func TestGetAdapterDisplayNameEmptyPowerShellOutput(t *testing.T) {
	restoreWindowsOSInfoSeams(t)
	systemDirectory := t.TempDir()
	wantPath := makeTestPowerShell(t, systemDirectory)
	getAdapterSystemDirectory = func() (string, error) { return systemDirectory, nil }
	runCommandOutput = func(_ context.Context, path string, _ ...string) ([]byte, error) {
		if path != wantPath {
			t.Fatalf("PowerShell path = %q, want %q", path, wantPath)
		}

		return nil, nil
	}

	if got := getAdapterDisplayName("Ethernet"); got != "" {
		t.Fatalf("getAdapterDisplayName() = %q, want empty", got)
	}
}

func TestGetAdapterDisplayNameSuccess(t *testing.T) {
	restoreWindowsOSInfoSeams(t)
	systemDirectory := t.TempDir()
	wantPath := makeTestPowerShell(t, systemDirectory)
	getAdapterSystemDirectory = func() (string, error) { return systemDirectory, nil }
	runCommandOutput = func(_ context.Context, path string, args ...string) ([]byte, error) {
		if path != wantPath {
			t.Fatalf("PowerShell path = %q, want %q", path, wantPath)
		}
		if len(args) != 3 || args[0] != "-NoProfile" || args[1] != "-Command" || !strings.Contains(args[2], "Ethernet''Adapter") {
			t.Fatalf("PowerShell args = %q, want trusted invocation with escaped interface name", args)
		}

		return []byte(" Intel(R) Ethernet Controller \r\n"), nil
	}

	if got, want := getAdapterDisplayName("Ethernet'Adapter"), "Intel(R) Ethernet Controller"; got != want {
		t.Fatalf("getAdapterDisplayName() = %q, want %q", got, want)
	}
}

func TestFindTrustedAdapterPowerShellIgnoresEnvironmentPaths(t *testing.T) {
	restoreWindowsOSInfoSeams(t)
	attackerDirectory := t.TempDir()

	attackerPowerShell := filepath.Join(attackerDirectory, "powershell.exe")

	if err := os.WriteFile(attackerPowerShell, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", attackerDirectory)

	t.Setenv("SystemRoot", attackerDirectory)

	trustedSystemDirectory := t.TempDir()
	wantPath := makeTestPowerShell(t, trustedSystemDirectory)
	getAdapterSystemDirectory = func() (string, error) { return trustedSystemDirectory, nil }

	if got := findTrustedAdapterPowerShellBinary(); got != wantPath {
		t.Fatalf("findTrustedAdapterPowerShellBinary() = %q, want %q", got, wantPath)
	}
}

func TestGetMEIDriverVersion(t *testing.T) {
	tests := []struct {
		name        string
		lookup      func(string) (string, error)
		run         func(context.Context, string, ...string) ([]byte, error)
		want        string
		wantInvoked bool
	}{
		{
			name:   "powerShell unavailable",
			lookup: func(string) (string, error) { return "", errors.New("not found") },
			want:   "",
		},
		{
			name:        "command fails",
			lookup:      func(string) (string, error) { return "powershell", nil },
			run:         func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("exec failed") },
			want:        "",
			wantInvoked: true,
		},
		{
			name:        "trim result",
			lookup:      func(string) (string, error) { return "powershell", nil },
			run:         func(context.Context, string, ...string) ([]byte, error) { return []byte(" 2542.0.52.0 \n"), nil },
			want:        "2542.0.52.0",
			wantInvoked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreWindowsOSInfoSeams(t)

			invoked := false

			lookupExecutable = tt.lookup
			runCommandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				invoked = true

				if tt.run == nil {
					return nil, nil
				}

				return tt.run(ctx, name, args...)
			}

			if got := GetMEIDriverVersion(); got != tt.want {
				t.Fatalf("GetMEIDriverVersion() = %q, want %q", got, tt.want)
			}

			if invoked != tt.wantInvoked {
				t.Fatalf("runCommandOutput invoked = %v, want %v", invoked, tt.wantInvoked)
			}
		})
	}
}
