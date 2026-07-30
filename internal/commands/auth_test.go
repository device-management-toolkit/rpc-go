/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerAuthFlags_Validate(t *testing.T) {
	tests := []struct {
		name    string
		flags   ServerAuthFlags
		wantErr string
	}{
		{
			name:  "no endpoint — no validation",
			flags: ServerAuthFlags{},
		},
		{
			name: "endpoint with token — ok",
			flags: ServerAuthFlags{
				AuthEndpoint: "/api/v1/authorize",
				AuthToken:    "tok",
			},
		},
		{
			name: "endpoint with username and password — ok",
			flags: ServerAuthFlags{
				AuthEndpoint: "/api/v1/authorize",
				AuthUsername: "user",
				AuthPassword: "pass",
			},
		},
		{
			name: "endpoint with no credentials — error",
			flags: ServerAuthFlags{
				AuthEndpoint: "/api/v1/authorize",
			},
			wantErr: "--auth-endpoint requires --auth-token or both --auth-username and --auth-password",
		},
		{
			name: "endpoint with username only — error",
			flags: ServerAuthFlags{
				AuthEndpoint: "/api/v1/authorize",
				AuthUsername: "user",
			},
			wantErr: "--auth-username requires --auth-password",
		},
		{
			name: "endpoint with password only — error",
			flags: ServerAuthFlags{
				AuthEndpoint: "/api/v1/authorize",
				AuthPassword: "pass",
			},
			wantErr: "--auth-password requires --auth-username",
		},
		{
			name: "username only without endpoint — error",
			flags: ServerAuthFlags{
				AuthUsername: "user",
			},
			wantErr: "--auth-username requires --auth-password",
		},
		{
			name: "password only without endpoint — error",
			flags: ServerAuthFlags{
				AuthPassword: "pass",
			},
			wantErr: "--auth-password requires --auth-username",
		},
		{
			name: "endpoint with token and username/password — token wins, ok",
			flags: ServerAuthFlags{
				AuthEndpoint: "/api/v1/authorize",
				AuthToken:    "tok",
				AuthUsername: "user",
				AuthPassword: "pass",
			},
		},
		{
			name: "devices endpoint with auth token — ok",
			flags: ServerAuthFlags{
				AuthEndpoint:    "/api/v1/authorize",
				AuthToken:       "tok",
				DevicesEndpoint: "http://localhost:8181/api/v1/devices",
			},
		},
		{
			name: "devices endpoint alone without auth endpoint — ok",
			flags: ServerAuthFlags{
				DevicesEndpoint: "http://localhost:8181/api/v1/devices",
			},
		},
		{
			name:    "devices endpoint with relative path — error",
			flags:   ServerAuthFlags{DevicesEndpoint: "/api/v1/devices"},
			wantErr: "--devices-endpoint must be an absolute HTTP(S) URL",
		},
		{
			name:    "devices endpoint with non-HTTP scheme — error",
			flags:   ServerAuthFlags{DevicesEndpoint: "ftp://localhost/devices"},
			wantErr: "--devices-endpoint must be an absolute HTTP(S) URL",
		},
		{
			name:    "devices endpoint with empty host — error",
			flags:   ServerAuthFlags{DevicesEndpoint: "http:///api/v1/devices"},
			wantErr: "--devices-endpoint must be an absolute HTTP(S) URL",
		},
		{
			name: "devices endpoint HTTPS — ok",
			flags: ServerAuthFlags{
				DevicesEndpoint: "https://console.example.com/api/v1/devices",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.flags.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServerAuthFlags_ValidateRequired(t *testing.T) {
	tests := []struct {
		name     string
		flags    ServerAuthFlags
		required bool
		wantErr  bool
	}{
		{
			name:     "not required — always ok",
			flags:    ServerAuthFlags{},
			required: false,
		},
		{
			name:     "required with token",
			flags:    ServerAuthFlags{AuthToken: "tok"},
			required: true,
		},
		{
			name:     "required with username and password",
			flags:    ServerAuthFlags{AuthUsername: "user", AuthPassword: "pass"},
			required: true,
		},
		{
			name:     "required with nothing",
			flags:    ServerAuthFlags{},
			required: true,
			wantErr:  true,
		},
		{
			name:     "required with username only",
			flags:    ServerAuthFlags{AuthUsername: "user"},
			required: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.flags.ValidateRequired(tt.required)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestServerAuthFlags_ApplyToRequest(t *testing.T) {
	tests := []struct {
		name       string
		flags      ServerAuthFlags
		wantHeader string
	}{
		{
			name:       "token sets bearer",
			flags:      ServerAuthFlags{AuthToken: "my-token"},
			wantHeader: "Bearer my-token",
		},
		{
			name:       "username/password sets basic",
			flags:      ServerAuthFlags{AuthUsername: "user", AuthPassword: "pass"},
			wantHeader: "Basic dXNlcjpwYXNz",
		},
		{
			name:       "token takes precedence over basic",
			flags:      ServerAuthFlags{AuthToken: "tok", AuthUsername: "user", AuthPassword: "pass"},
			wantHeader: "Bearer tok",
		},
		{
			name:       "no credentials — no header",
			flags:      ServerAuthFlags{},
			wantHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
			tt.flags.ApplyToRequest(req)

			assert.Equal(t, tt.wantHeader, req.Header.Get("Authorization"))
		})
	}
}

func TestServerAuthFlags_WarnIfInsecure(t *testing.T) {
	tests := []struct {
		name          string
		flags         ServerAuthFlags
		cliArgs       []string
		expectWarning bool
		description   string
	}{
		{
			name:          "token from env - no warning",
			flags:         ServerAuthFlags{AuthToken: "env-token"},
			cliArgs:       []string{"rpc", "version"}, // No auth flags
			expectWarning: false,
			description:   "Token from environment variable should not warn",
		},
		{
			name:          "token from CLI - warning",
			flags:         ServerAuthFlags{AuthToken: "cli-token"},
			cliArgs:       []string{"rpc", "version", "--auth-token", "cli-token"},
			expectWarning: true,
			description:   "Token from CLI flag should warn",
		},
		{
			name: "basic auth from env - no warning",
			flags: ServerAuthFlags{
				AuthUsername: "user",
				AuthPassword: "pass",
			},
			cliArgs:       []string{"rpc", "version"}, // No auth flags
			expectWarning: false,
			description:   "Basic auth from environment should not warn",
		},
		{
			name: "basic auth from CLI - warning",
			flags: ServerAuthFlags{
				AuthUsername: "user",
				AuthPassword: "pass",
			},
			cliArgs:       []string{"rpc", "version", "--auth-username", "user", "--auth-password", "pass"},
			expectWarning: true,
			description:   "Basic auth from CLI should warn",
		},
		{
			name: "only password on CLI - partial warning",
			flags: ServerAuthFlags{
				AuthUsername: "user",
				AuthPassword: "pass",
			},
			cliArgs:       []string{"rpc", "version", "--auth-password", "pass"},
			expectWarning: true,
			description:   "Password from CLI should warn even if username from env",
		},
		{
			name:          "no credentials - no warning",
			flags:         ServerAuthFlags{},
			cliArgs:       []string{"rpc", "version"},
			expectWarning: false,
			description:   "No credentials should not warn",
		},
		{
			name: "username only from CLI - warning",
			flags: ServerAuthFlags{
				AuthUsername: "user",
			},
			cliArgs:       []string{"rpc", "version", "--auth-username", "user"},
			expectWarning: true,
			description:   "Username only from CLI should warn",
		},
		{
			name: "password only from CLI - warning",
			flags: ServerAuthFlags{
				AuthPassword: "pass",
			},
			cliArgs:       []string{"rpc", "version", "--auth-password", "pass"},
			expectWarning: true,
			description:   "Password only from CLI should warn",
		},
		{
			name: "token from CLI even with env vars set - warning",
			flags: ServerAuthFlags{
				AuthToken: "cli-token",
			},
			cliArgs:       []string{"rpc", "version", "--auth-token", "cli-token"},
			expectWarning: true,
			description:   "Token from CLI should warn even if AUTH_TOKEN env var is also set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore os.Args
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			// Set os.Args to simulate CLI invocation
			os.Args = tt.cliArgs

			// Capture log output
			var logBuf bytes.Buffer

			originalOutput := logrus.StandardLogger().Out
			originalLevel := logrus.GetLevel()

			logrus.SetOutput(&logBuf)
			logrus.SetLevel(logrus.WarnLevel) // Ensure warnings are logged

			defer func() {
				logrus.SetOutput(originalOutput)
				logrus.SetLevel(originalLevel)
			}()

			// Call the warning function
			tt.flags.WarnIfInsecure()

			// Check if warning was logged
			logOutput := logBuf.String()
			hasWarning := strings.Contains(logOutput, "SECURITY WARNING")

			if hasWarning != tt.expectWarning {
				t.Errorf("%s: expected warning=%v, got warning=%v\nLog output:\n%s",
					tt.description, tt.expectWarning, hasWarning, logOutput)
			}

			// If we expect a warning, verify it contains key elements
			if tt.expectWarning {
				assert.Contains(t, logOutput, "SECURITY WARNING", "Warning should contain security notice")
				assert.Contains(t, logOutput, "visible in process listings", "Warning should mention process visibility")
				assert.Contains(t, logOutput, "Use environment variables instead", "Warning should suggest env vars")
			}
		})
	}
}

func TestServerAuthFlags_AfterApply(t *testing.T) {
	// Save and restore os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Simulate CLI with auth token
	os.Args = []string{"rpc", "version", "--auth-token", "test-token"}

	// Test that AfterApply calls WarnIfInsecure
	flags := ServerAuthFlags{
		AuthToken: "test-token",
	}

	// Capture log output
	var logBuf bytes.Buffer

	originalOutput := logrus.StandardLogger().Out
	originalLevel := logrus.GetLevel()

	logrus.SetOutput(&logBuf)
	logrus.SetLevel(logrus.WarnLevel)

	defer func() {
		logrus.SetOutput(originalOutput)
		logrus.SetLevel(originalLevel)
	}()

	// Call AfterApply
	err := flags.AfterApply()

	// Should not return error
	assert.NoError(t, err, "AfterApply should not return error")

	// Should have triggered warning
	logOutput := logBuf.String()
	assert.Contains(t, logOutput, "SECURITY WARNING", "AfterApply should trigger warning for CLI credentials")
}
