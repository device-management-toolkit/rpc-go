//go:build windows

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

func restoreWindowsOSInfoSeams(t *testing.T) {
	originalLookupExecutable := lookupExecutable
	originalRunCommandOutput := runCommandOutput

	t.Cleanup(func() {
		lookupExecutable = originalLookupExecutable
		runCommandOutput = originalRunCommandOutput
	})
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
