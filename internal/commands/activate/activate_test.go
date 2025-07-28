/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// MockPasswordReader for testing password scenarios
type MockPasswordReaderSuccess struct{}

func (mpr *MockPasswordReaderSuccess) ReadPassword() (string, error) {
	return utils.TestPassword, nil
}

type MockPasswordReaderFail struct{}

func (mpr *MockPasswordReaderFail) ReadPassword() (string, error) {
	return "", errors.New("Read password failed")
}

func TestActivateCmd_Structure(t *testing.T) {
	// Test that ActivateCmd has the correct structure
	cmd := &ActivateCmd{}

	// Test basic field access to ensure struct is correct
	cmd.Local = true
	cmd.URL = "test"
	cmd.CCM = true
}

func TestActivateCmd_Validate_Remote(t *testing.T) {
	tests := []struct {
		name    string
		cmd     ActivateCmd
		wantErr bool
	}{
		{
			name: "valid remote with URL and profile",
			cmd: ActivateCmd{
				URL:     "wss://192.168.1.1/activate",
				Profile: "test-profile",
			},
			wantErr: false,
		},
		{
			name: "remote with URL but no profile",
			cmd: ActivateCmd{
				URL: "wss://192.168.1.1/activate",
			},
			wantErr: true,
		},
		{
			name: "conflicting local and remote flags",
			cmd: ActivateCmd{
				Local:   true,
				URL:     "wss://192.168.1.1/activate",
				Profile: "test-profile",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ActivateCmd.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestActivateCmd_Validate_Local(t *testing.T) {
	tests := []struct {
		name    string
		cmd     ActivateCmd
		wantErr bool
	}{
		{
			name: "valid local with CCM",
			cmd: ActivateCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: utils.TestPassword},
				Local:      true,
				CCM:        true,
			},
			wantErr: false,
		},
		{
			name: "valid local with ACM",
			cmd: ActivateCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: utils.TestPassword},
				Local:      true,
				ACM:        true,
			},
			wantErr: false,
		},
		{
			name: "valid local with stopConfig",
			cmd: ActivateCmd{
				Local:      true,
				StopConfig: true,
			},
			wantErr: false,
		},
		{
			name: "implicit local with CCM flag",
			cmd: ActivateCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: utils.TestPassword},
				CCM:        true,
			},
			wantErr: false,
		},
		{
			name: "local without mode selection",
			cmd: ActivateCmd{
				Local: true,
			},
			wantErr: true,
		},
		{
			name: "conflicting CCM and ACM",
			cmd: ActivateCmd{
				Local: true,
				CCM:   true,
				ACM:   true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ActivateCmd.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestActivateCmd_Validate_NoMode(t *testing.T) {
	tests := []struct {
		name    string
		cmd     ActivateCmd
		wantErr bool
	}{
		{
			name:    "no flags specified",
			cmd:     ActivateCmd{},
			wantErr: true,
		},
		{
			name: "only common flags",
			cmd: ActivateCmd{
				DNS:      "test.com",
				Hostname: "testhost",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ActivateCmd.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestActivateCmd_hasLocalActivationFlags(t *testing.T) {
	tests := []struct {
		name string
		cmd  ActivateCmd
		want bool
	}{
		{
			name: "CCM flag",
			cmd:  ActivateCmd{CCM: true},
			want: true,
		},
		{
			name: "ACM flag",
			cmd:  ActivateCmd{ACM: true},
			want: true,
		},
		{
			name: "StopConfig flag",
			cmd:  ActivateCmd{StopConfig: true},
			want: true,
		},
		{
			name: "AMT Password",
			cmd:  ActivateCmd{AMTBaseCmd: commands.AMTBaseCmd{Password: "password123"}},
			want: true,
		},
		{
			name: "Provisioning cert",
			cmd:  ActivateCmd{ProvisioningCert: "cert123"},
			want: true,
		},
		{
			name: "Provisioning cert password",
			cmd:  ActivateCmd{ProvisioningCertPwd: "certpwd123"},
			want: true,
		},
		{
			name: "Skip IP renew",
			cmd:  ActivateCmd{SkipIPRenew: true},
			want: true,
		},
		{
			name: "no local flags",
			cmd:  ActivateCmd{URL: "test", Profile: "test"},
			want: false,
		},
		{
			name: "only common flags",
			cmd:  ActivateCmd{DNS: "test.com", Hostname: "testhost"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cmd.hasLocalActivationFlags(); got != tt.want {
				t.Errorf("ActivateCmd.hasLocalActivationFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestActivateCmd_ModeDetection tests the mode detection logic without executing activation
func TestActivateCmd_ModeDetection(t *testing.T) {
	tests := []struct {
		name         string
		cmd          ActivateCmd
		expectRemote bool
		expectLocal  bool
	}{
		{
			name: "URL flag triggers remote mode",
			cmd: ActivateCmd{
				URL:     "wss://rps.example.com/activate",
				Profile: "test-profile",
			},
			expectRemote: true,
			expectLocal:  false,
		},
		{
			name: "CCM flag triggers local mode",
			cmd: ActivateCmd{
				CCM: true,
			},
			expectRemote: false,
			expectLocal:  true,
		},
		{
			name: "Local flag triggers local mode",
			cmd: ActivateCmd{
				Local: true,
				ACM:   true,
			},
			expectRemote: false,
			expectLocal:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test mode detection by checking which method would be called
			isRemote := tt.cmd.URL != ""
			isLocal := tt.cmd.Local || tt.cmd.hasLocalActivationFlags()

			if isRemote != tt.expectRemote {
				t.Errorf("Expected remote mode: %v, got: %v", tt.expectRemote, isRemote)
			}

			if isLocal != tt.expectLocal {
				t.Errorf("Expected local mode: %v, got: %v", tt.expectLocal, isLocal)
			}
		})
	}
}

func TestActivateCmd_Validate_ConflictingFlags(t *testing.T) {
	tests := []struct {
		name    string
		cmd     ActivateCmd
		wantErr bool
		errMsg  string
	}{
		{
			name: "URL with CCM flag should fail",
			cmd: ActivateCmd{
				URL:     "wss://rps.example.com/activate",
				Profile: "test-profile",
				CCM:     true,
			},
			wantErr: true,
			errMsg:  "--ccm flag is only valid for local activation, not with --url",
		},
		{
			name: "URL with ACM flag should fail",
			cmd: ActivateCmd{
				URL:     "wss://rps.example.com/activate",
				Profile: "test-profile",
				ACM:     true,
			},
			wantErr: true,
			errMsg:  "--acm flag is only valid for local activation, not with --url",
		},
		{
			name: "URL with stopConfig should fail",
			cmd: ActivateCmd{
				URL:        "wss://rps.example.com/activate",
				Profile:    "test-profile",
				StopConfig: true,
			},
			wantErr: true,
			errMsg:  "--stopConfig flag is only valid for local activation, not with --url",
		},
		{
			name: "URL with AMT password should fail",
			cmd: ActivateCmd{
				URL:        "wss://rps.example.com/activate",
				Profile:    "test-profile",
				AMTBaseCmd: commands.AMTBaseCmd{Password: "password123"},
			},
			wantErr: true,
			errMsg:  "--amtPassword flag is only valid for local activation, not with --url",
		},
		{
			name: "URL with provisioning cert should fail",
			cmd: ActivateCmd{
				URL:              "wss://rps.example.com/activate",
				Profile:          "test-profile",
				ProvisioningCert: "cert123",
			},
			wantErr: true,
			errMsg:  "--provisioningCert flag is only valid for local activation, not with --url",
		},
		{
			name: "URL with skipIPRenew should fail",
			cmd: ActivateCmd{
				URL:         "wss://rps.example.com/activate",
				Profile:     "test-profile",
				SkipIPRenew: true,
			},
			wantErr: true,
			errMsg:  "--skipIPRenew flag is only valid for local activation, not with --url",
		},
		{
			name: "Valid remote activation should pass",
			cmd: ActivateCmd{
				URL:          "wss://rps.example.com/activate",
				Profile:      "test-profile",
				DNS:          "example.com",
				Hostname:     "testhost",
				FriendlyName: "Test Device",
				Proxy:        "http://proxy:8080",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ActivateCmd.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && err.Error() != tt.errMsg {
				t.Errorf("ActivateCmd.Validate() error = %v, wantErrMsg %v", err.Error(), tt.errMsg)
			}
		})
	}
}
