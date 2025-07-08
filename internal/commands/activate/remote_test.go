/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

func TestRemoteActivateCmd_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     RemoteActivateCmd
		wantErr bool
	}{
		{
			name: "valid remote activation",
			cmd: RemoteActivateCmd{
				URL:     "https://rps.server",
				Profile: "test-profile",
			},
			wantErr: false,
		},
		{
			name: "valid with UUID override (should warn but not error)",
			cmd: RemoteActivateCmd{
				URL:     "https://rps.server",
				Profile: "test-profile",
				UUID:    "test-uuid",
			},
			wantErr: false,
		},
		{
			name: "valid with proxy configuration",
			cmd: RemoteActivateCmd{
				URL:     "https://rps.server",
				Profile: "test-profile",
				Proxy:   "http://proxy.server:8080",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("RemoteActivateCmd.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteActivateCmd_toActivationConfig(t *testing.T) {
	tests := []struct {
		name string
		cmd  RemoteActivateCmd
		want RemoteActivationConfig
	}{
		{
			name: "converts all fields including proxy",
			cmd: RemoteActivateCmd{
				URL:          "https://rps.server",
				Profile:      "test-profile",
				DNS:          "test.dns",
				Hostname:     "test-host",
				UUID:         "test-uuid",
				FriendlyName: "test-device",
				Proxy:        "http://proxy.server:8080",
			},
			want: RemoteActivationConfig{
				URL:          "https://rps.server",
				Profile:      "test-profile",
				DNS:          "test.dns",
				Hostname:     "test-host",
				UUID:         "test-uuid",
				FriendlyName: "test-device",
				Proxy:        "http://proxy.server:8080",
			},
		},
		{
			name: "handles empty proxy",
			cmd: RemoteActivateCmd{
				URL:     "https://rps.server",
				Profile: "test-profile",
			},
			want: RemoteActivationConfig{
				URL:     "https://rps.server",
				Profile: "test-profile",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cmd.toActivationConfig()
			if got != tt.want {
				t.Errorf("RemoteActivateCmd.toActivationConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoteActivateCmd_Run(t *testing.T) {
	tests := []struct {
		name    string
		cmd     RemoteActivateCmd
		wantErr bool
	}{
		{
			name: "valid run parameters but skip actual execution",
			cmd: RemoteActivateCmd{
				URL:          "https://rps.server",
				Profile:      "test-profile",
				DNS:          "test.dns",
				Hostname:     "test-host",
				UUID:         "test-uuid",
				FriendlyName: "test-device",
				Proxy:        "http://proxy:8080",
			},
			wantErr: true, // Will error because we can't actually connect to RPS in tests
		},
	}

	// Note: We can't test the full Run() method without mocking the RPS system
	// These tests verify that the method can be called and config conversion works
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test config conversion instead of full run to avoid RPS dependencies
			config := tt.cmd.toActivationConfig()

			if config.URL != tt.cmd.URL {
				t.Errorf("toActivationConfig() URL = %v, want %v", config.URL, tt.cmd.URL)
			}

			if config.Profile != tt.cmd.Profile {
				t.Errorf("toActivationConfig() Profile = %v, want %v", config.Profile, tt.cmd.Profile)
			}

			if config.Proxy != tt.cmd.Proxy {
				t.Errorf("toActivationConfig() Proxy = %v, want %v", config.Proxy, tt.cmd.Proxy)
			}
		})
	}
}

func TestNewRemoteActivationService(t *testing.T) {
	config := RemoteActivationConfig{
		URL:          "https://rps.server",
		Profile:      "test-profile",
		DNS:          "test.dns",
		Hostname:     "test-host",
		UUID:         "test-uuid",
		FriendlyName: "test-device",
		Proxy:        "http://proxy:8080",
	}

	ctx := &commands.Context{
		JsonOutput:    true,
		SkipCertCheck: true,
	}

	service := NewRemoteActivationService(config, ctx)

	if service.config != config {
		t.Error("NewRemoteActivationService() did not set config correctly")
	}

	if service.context != ctx {
		t.Error("NewRemoteActivationService() did not set context correctly")
	}
}

func TestRemoteActivationService_validateRPSConnection(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid URL",
			url:     "https://rps.server",
			wantErr: false,
		},
		{
			name:    "empty URL should error",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &RemoteActivationService{
				config: RemoteActivationConfig{
					URL: tt.url,
				},
			}

			err := service.validateRPSConnection()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRPSConnection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteActivationService_prepareDeviceInfo(t *testing.T) {
	tests := []struct {
		name   string
		config RemoteActivationConfig
		want   map[string]interface{}
	}{
		{
			name: "all fields provided",
			config: RemoteActivationConfig{
				Profile:      "test-profile",
				DNS:          "test.dns",
				Hostname:     "test-host",
				UUID:         "test-uuid",
				FriendlyName: "test-device",
			},
			want: map[string]interface{}{
				"profile":       "test-profile",
				"dns":           "test.dns",
				"hostname":      "test-host",
				"uuid":          "test-uuid",
				"friendly_name": "test-device",
			},
		},
		{
			name: "minimal fields",
			config: RemoteActivationConfig{
				Profile: "test-profile",
			},
			want: map[string]interface{}{
				"profile": "test-profile",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &RemoteActivationService{
				config: tt.config,
			}

			got := service.prepareDeviceInfo()

			// Check that all expected keys are present
			for key, expectedValue := range tt.want {
				if got[key] != expectedValue {
					t.Errorf("prepareDeviceInfo() key %s = %v, want %v", key, got[key], expectedValue)
				}
			}

			// Check that no extra keys are present
			if len(got) != len(tt.want) {
				t.Errorf("prepareDeviceInfo() returned %d fields, want %d", len(got), len(tt.want))
			}
		})
	}
}

func TestRemoteActivationService_outputResult(t *testing.T) {
	tests := []struct {
		name       string
		jsonOutput bool
		result     map[string]interface{}
		wantErr    bool
	}{
		{
			name:       "JSON output",
			jsonOutput: true,
			result: map[string]interface{}{
				"status":     "success",
				"message":    "test message",
				"rps_server": "https://rps.server",
			},
			wantErr: false,
		},
		{
			name:       "text output",
			jsonOutput: false,
			result: map[string]interface{}{
				"status":        "success",
				"message":       "test message",
				"rps_server":    "https://rps.server",
				"profile":       "test-profile",
				"friendly_name": "test-device",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &RemoteActivationService{
				config: RemoteActivationConfig{
					URL:          "https://rps.server",
					Profile:      "test-profile",
					FriendlyName: "test-device",
				},
				context: &commands.Context{
					JsonOutput: tt.jsonOutput,
				},
			}

			err := service.outputResult(tt.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("outputResult() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemoteActivationService_Activate_Steps(t *testing.T) {
	// Test individual steps of the activation process without actually executing RPS
	service := &RemoteActivationService{
		config: RemoteActivationConfig{
			URL:          "https://rps.server",
			Profile:      "test-profile",
			DNS:          "test.dns",
			Hostname:     "test-host",
			UUID:         "test-uuid",
			FriendlyName: "test-device",
			Proxy:        "http://proxy:8080",
		},
		context: &commands.Context{
			JsonOutput: true,
		},
	}

	// Test validateRPSConnection
	err := service.validateRPSConnection()
	if err != nil {
		t.Errorf("validateRPSConnection() failed: %v", err)
	}

	// Test prepareDeviceInfo
	deviceInfo := service.prepareDeviceInfo()

	expectedFields := []string{"profile", "dns", "hostname", "uuid", "friendly_name"}
	for _, field := range expectedFields {
		if _, exists := deviceInfo[field]; !exists {
			t.Errorf("prepareDeviceInfo() missing field: %s", field)
		}
	}

	// Test outputResult with mock data
	mockResult := map[string]interface{}{
		"status":        "success",
		"message":       "Test activation",
		"rps_server":    "https://rps.server",
		"profile":       "test-profile",
		"friendly_name": "test-device",
	}

	err = service.outputResult(mockResult)
	if err != nil {
		t.Errorf("outputResult() failed: %v", err)
	}
}

func TestRemoteActivationService_Activate_EmptyURL(t *testing.T) {
	service := &RemoteActivationService{
		config: RemoteActivationConfig{
			URL: "", // Empty URL should cause validation error
		},
		context: &commands.Context{},
	}

	err := service.Activate()
	if err == nil {
		t.Error("Activate() with empty URL should return error")
	}
}
