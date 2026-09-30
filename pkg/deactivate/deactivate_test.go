/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package deactivate

import (
	"errors"
	"os"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var errUnexpectedPrompt = errors.New("unexpected password prompt")

// noPrompt fails every password prompt so a test can never block on stdin.
type noPrompt struct{}

func (noPrompt) ReadPassword() (string, error) { return "", errUnexpectedPrompt }

func (noPrompt) ReadPasswordWithConfirmation(_, _ string) (string, error) {
	return "", errUnexpectedPrompt
}

func TestMain(m *testing.M) {
	utils.PR = noPrompt{}

	os.Exit(m.Run())
}

// requireReachedAMT asserts validation passed and the call failed only on AMT access.
func requireReachedAMT(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, utils.IncorrectPermissions) && !errors.Is(err, utils.HECIDriverNotDetected) {
		t.Fatalf("expected validation to pass and AMT access to fail, got: %v", err)
	}
}

func TestRun_ValidOptionsReachAMT(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{"defaults", Options{}},
		{"partial unprovision", Options{AMTPassword: "P@ssw0rd", PartialUnprovision: true}},
		{"console cleanup with credentials", Options{
			AuthEndpoint: "https://console.example.com/api/v1/authorize",
			AuthUsername: "user", AuthPassword: "pass",
		}},
		{"console cleanup with token", Options{
			AuthToken: "token", DevicesEndpoint: "https://console.example.com/api/v1/devices",
		}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			requireReachedAMT(t, Run(tt.opts))
		})
	}
}

func TestRun_InvalidConsoleOptionsRejectedBeforeAMTAccess(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{"relative devices endpoint", Options{DevicesEndpoint: "console.example.com/api/v1/devices"}, "--devices-endpoint must be an absolute HTTP(S) URL"},
		{"username without password", Options{AuthUsername: "user"}, "--auth-username requires --auth-password"},
		{"password without username", Options{AuthPassword: "pass"}, "--auth-password requires --auth-username"},
		{"auth endpoint without credentials", Options{AuthEndpoint: "https://console.example.com/api/v1/authorize"}, "--auth-endpoint requires --auth-token"},
		{"relative auth endpoint", Options{AuthEndpoint: "/api/v1/authorize", AuthUsername: "user", AuthPassword: "pass"}, "AuthEndpoint must be an absolute HTTP(S) URL"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorContains(t, Run(tt.opts), tt.wantErr)
		})
	}
}

func TestNewCommand_MapsOptions(t *testing.T) {
	cmd, ctx := newCommand(Options{
		AMTPassword:        "amt-pass",
		PartialUnprovision: true,
		SkipAMTCertCheck:   true,
		UUID:               "4c4c4544-0000-1000-8000-000000000000",
		SkipCertCheck:      true,
		TenantID:           "tenant-1",
		AuthToken:          "token",
		AuthUsername:       "user",
		AuthPassword:       "pass",
		AuthEndpoint:       "https://console.example.com/api/v1/authorize",
		DevicesEndpoint:    "https://console.example.com/api/v1/devices",
	})

	assert.Equal(t, &commands.DeactivateCmd{
		Local:              true,
		PartialUnprovision: true,
		UUID:               "4c4c4544-0000-1000-8000-000000000000",
	}, cmd)
	assert.Equal(t, &commands.Context{
		AMTPassword:      "amt-pass",
		SkipAMTCertCheck: true,
		SkipCertCheck:    true,
		TenantID:         "tenant-1",
		ServerAuthFlags: commands.ServerAuthFlags{
			AuthToken:       "token",
			AuthUsername:    "user",
			AuthPassword:    "pass",
			AuthEndpoint:    "https://console.example.com/api/v1/authorize",
			DevicesEndpoint: "https://console.example.com/api/v1/devices",
		},
	}, ctx)
}
