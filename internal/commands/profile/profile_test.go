/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestProfileFetcher_FetchProfile(t *testing.T) {
	// Create a test profile with the correct nested structure
	testProfile := config.Configuration{
		Name: "test-profile",
		Configuration: config.RemoteManagement{
			AMTSpecific: config.AMTSpecific{
				ControlMode:   "acmactivate",
				AdminPassword: "TestPassword123!",
			},
			Network: config.Network{
				Wired: config.Wired{
					DHCPEnabled: true,
				},
			},
			TLS: config.TLS{
				Enabled: true,
			},
		},
	}

	// Test cases
	tests := []struct {
		name        string
		setupServer func() *httptest.Server
		token       string
		username    string 
		password    string
		expectError bool
	}{
		{
			name: "Fetch JSON profile without auth",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(testProfile)
				}))
			},
			expectError: false,
		},
		{
			name: "Fetch YAML profile without auth",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/yaml")
					yaml.NewEncoder(w).Encode(testProfile)
				}))
			},
			expectError: false,
		},
		{
			name: "Fetch profile with Bearer token",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					auth := r.Header.Get("Authorization")
					if auth != "Bearer test-token-123" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(testProfile)
				}))
			},
			token:       "test-token-123",
			expectError: false,
		},
		{
			name: "Unauthorized without token",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					auth := r.Header.Get("Authorization")
					if auth == "" {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte("Authentication required"))
						return
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(testProfile)
				}))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test server
			server := tt.setupServer()
			defer server.Close()

			// Create fetcher
			fetcher := &ProfileFetcher{
				URL:      server.URL + "/profile",
				Token:    tt.token,
				Username: tt.username,
				Password: tt.password,
			}

			// Fetch profile
			profile, err := fetcher.FetchProfile()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testProfile.Name, profile.Name)
				assert.Equal(t, testProfile.Configuration.AMTSpecific.ControlMode, 
					profile.Configuration.AMTSpecific.ControlMode)
			}
		})
	}
}

func TestProfileFetcher_EncryptedProfile(t *testing.T) {
	// Test encrypted profile response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock encrypted response format
		encryptedResponse := map[string]interface{}{
			"filename": "test-profile.yaml",
			"content":  "mock-encrypted-content-here",
			"key":      "mock-encryption-key-123",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(encryptedResponse)
	}))
	defer server.Close()

	fetcher := &ProfileFetcher{
		URL: server.URL + "/profile",
	}

	// This test will fail because we don't have actual encrypted data
	// But it demonstrates the encrypted response detection
	_, err := fetcher.FetchProfile()
	
	// We expect this to fail with decryption error since we're using mock data
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestProfileFetcher_Authentication(t *testing.T) {
	// Test username/password authentication
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			var authReq AuthRequest
			if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if authReq.Username == "testuser" && authReq.Password == "testpass" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(AuthResponse{Token: "generated-token-456"})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		// Profile endpoint
		auth := r.Header.Get("Authorization")
		if auth != "Bearer generated-token-456" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		testProfile := map[string]interface{}{
			"name": "auth-test-profile",
			"configuration": map[string]interface{}{
				"amtSpecific": map[string]interface{}{
					"controlMode": "ccmactivate",
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testProfile)
	}))
	defer server.Close()

	fetcher := &ProfileFetcher{
		URL:      server.URL + "/profile",
		Username: "testuser",
		Password: "testpass",
	}

	profile, err := fetcher.FetchProfile()
	require.NoError(t, err)
	assert.Equal(t, "auth-test-profile", profile.Name)
}

func TestProfileCmd_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cmd         ProfileCmd
		expectError bool
	}{
		{
			name: "Valid file source",
			cmd: ProfileCmd{
				File: "profile.yaml",
			},
			expectError: false,
		},
		{
			name: "Valid URL source with token",
			cmd: ProfileCmd{
				URL:   "https://example.com/profile",
				Token: "test-token",
			},
			expectError: false,
		},
		{
			name: "Valid URL source with username/password",
			cmd: ProfileCmd{
				URL:      "https://example.com/profile",
				Username: "user",
				Password: "pass",
			},
			expectError: false,
		},
		{
			name:        "No source specified",
			cmd:         ProfileCmd{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProfileCmd_LoadProfileFromFile(t *testing.T) {
	// Create a temporary profile file
	tempFile, err := os.CreateTemp("", "test-profile-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write a simple profile structure matching the YAML format
	yamlContent := `
name: file-test-profile
configuration:
  amtSpecific:
    controlMode: ccmactivate
    adminPassword: TestFilePassword
  network:
    wired:
      dhcpEnabled: true
  tls:
    enabled: false
`

	_, err = tempFile.WriteString(yamlContent)
	require.NoError(t, err)
	tempFile.Close()

	// Test loading from file
	cmd := ProfileCmd{
		File: tempFile.Name(),
	}

	profile, err := cmd.loadProfile(nil)
	require.NoError(t, err)
	assert.Equal(t, "file-test-profile", profile.Name)
	assert.Equal(t, "ccmactivate", profile.Configuration.AMTSpecific.ControlMode)
	assert.Equal(t, "TestFilePassword", profile.Configuration.AMTSpecific.AdminPassword)
	assert.True(t, profile.Configuration.Network.Wired.DHCPEnabled)
	assert.False(t, profile.Configuration.TLS.Enabled)
}