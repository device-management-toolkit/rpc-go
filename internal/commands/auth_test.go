/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"context"
	"net/http"
	"testing"

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
