/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/managementpresence"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/remoteaccess"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/userinitiatedconnection"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestCIRACmd_Structure(t *testing.T) {
	// Test that CIRACmd has the correct structure
	cmd := &CIRACmd{}

	// Test basic field access to ensure struct is correct
	cmd.Password = "amt123"
	cmd.MPSPassword = "mps123"
	cmd.MPSAddress = "https://mps.example.com"
	cmd.MPSCert = "test-cert"
	cmd.EnvironmentDetection = []string{"example.com"}

	assert.Equal(t, "amt123", cmd.Password)
	assert.Equal(t, "mps123", cmd.MPSPassword)
	assert.Equal(t, "https://mps.example.com", cmd.MPSAddress)
	assert.Equal(t, "test-cert", cmd.MPSCert)
	assert.Equal(t, []string{"example.com"}, cmd.EnvironmentDetection)
}

func TestCIRACmd_Validate(t *testing.T) {
	tests := []struct {
		name        string
		cmd         CIRACmd
		wantErr     bool
		description string
	}{
		{
			name: "all_fields_provided",
			cmd: CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "amt123",
					},
				},
				MPSPassword:          "mps123",
				MPSAddress:           "https://mps.example.com",
				MPSCert:              "test-cert",
				EnvironmentDetection: []string{"example.com"},
			},
			wantErr:     false,
			description: "should succeed when all fields are provided",
		},

		{
			name: "missing_mps_password",
			cmd: CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "amt123",
					},
				},
				MPSPassword:          "", // Will be prompted
				MPSAddress:           "https://mps.example.com",
				MPSCert:              "test-cert",
				EnvironmentDetection: []string{"example.com"},
			},
			wantErr:     true, // Will fail in test since no interactive input
			description: "should prompt for MPS password when missing",
		},
		{
			name: "missing_mps_address",
			cmd: CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "amt123",
					},
				},
				MPSPassword:          "mps123",
				MPSAddress:           "", // Required
				MPSCert:              "test-cert",
				EnvironmentDetection: []string{"example.com"},
			},
			wantErr:     true,
			description: "should fail when MPS address is missing",
		},
		{
			name: "invalid_mps_address",
			cmd: CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "amt123",
					},
				},
				MPSPassword:          "mps123",
				MPSAddress:           "invalid-url", // Invalid format
				MPSCert:              "test-cert",
				EnvironmentDetection: []string{"example.com"},
			},
			wantErr:     true,
			description: "should fail when MPS address is invalid",
		},
		{
			name: "missing_mps_cert",
			cmd: CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "amt123",
					},
				},
				MPSPassword:          "mps123",
				MPSAddress:           "https://mps.example.com",
				MPSCert:              "", // Required
				EnvironmentDetection: []string{"example.com"},
			},
			wantErr:     true,
			description: "should fail when MPS certificate is missing",
		},
		{
			name: "empty_environment_detection",
			cmd: CIRACmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "amt123",
					},
				},
				MPSPassword:          "mps123",
				MPSAddress:           "https://mps.example.com",
				MPSCert:              "test-cert",
				EnvironmentDetection: []string{}, // Will be auto-generated
			},
			wantErr:     false,
			description: "should succeed and auto-generate environment detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()

			if tt.wantErr {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestCIRACmd_Run(t *testing.T) {
	t.Run("successful_cira_configuration", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (existing policies and MPS)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{
			{Name: "test-mps"},
		}, nil)

		// Mock AddRemoteAccessPolicyRule calls
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(0), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)

		// Mock GetRemoteAccessPolicies (after adding rules)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{
			{}, // periodic policy
			{}, // user-initiated policy
		}, nil)

		// Mock PutRemoteAccessPolicyAppliesToMPS calls
		mockWSMAN.EXPECT().PutRemoteAccessPolicyAppliesToMPS(gomock.Any()).Return(remoteaccess.Body{}, nil).Times(2)

		// Mock RequestStateChangeCIRA
		mockWSMAN.EXPECT().RequestStateChangeCIRA().Return(userinitiatedconnection.RequestStateChange_OUTPUT{}, nil)

		// Mock GetEnvironmentDetectionSettings
		mockWSMAN.EXPECT().GetEnvironmentDetectionSettings().Return(environmentdetection.EnvironmentDetectionSettingDataResponse{
			ElementName:        "Environment Detection",
			InstanceID:         "env-id",
			DetectionAlgorithm: 1,
		}, nil)

		// Mock PutEnvironmentDetectionSettings
		mockWSMAN.EXPECT().PutEnvironmentDetectionSettings(gomock.Any()).Return(environmentdetection.EnvironmentDetectionSettingDataResponse{}, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("device_not_activated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 0,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device is not activated")
	})

	t.Run("clear_cira_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations - simulate error
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return(nil, errors.New("clear cira error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to clear existing CIRA configuration")
	})

	t.Run("add_trusted_root_cert_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert to return an error (not the "already exists" error)
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("", errors.New("cert add error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add trusted root certificate")
	})

	t.Run("add_trusted_root_cert_already_exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert to return "already exists" error (should continue)
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("", errors.New("Root Certificate already exists and must be removed before continuing"))

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{
			{Name: "test-mps"},
		}, nil)

		// Mock AddRemoteAccessPolicyRule calls
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(0), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)

		// Mock GetRemoteAccessPolicies (after adding rules)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{
			{}, // periodic policy
			{}, // user-initiated policy
		}, nil)

		// Mock PutRemoteAccessPolicyAppliesToMPS calls
		mockWSMAN.EXPECT().PutRemoteAccessPolicyAppliesToMPS(gomock.Any()).Return(remoteaccess.Body{}, nil).Times(2)

		// Mock RequestStateChangeCIRA
		mockWSMAN.EXPECT().RequestStateChangeCIRA().Return(userinitiatedconnection.RequestStateChange_OUTPUT{}, nil)

		// Mock GetEnvironmentDetectionSettings
		mockWSMAN.EXPECT().GetEnvironmentDetectionSettings().Return(environmentdetection.EnvironmentDetectionSettingDataResponse{
			ElementName:        "Environment Detection",
			InstanceID:         "env-id",
			DetectionAlgorithm: 1,
		}, nil)

		// Mock PutEnvironmentDetectionSettings
		mockWSMAN.EXPECT().PutEnvironmentDetectionSettings(gomock.Any()).Return(environmentdetection.EnvironmentDetectionSettingDataResponse{}, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err) // Should continue despite "already exists" error
	})

	t.Run("add_mps_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS to return an error
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, errors.New("add mps error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add MPS server")
	})

	t.Run("no_mps_found_after_add", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS) - return empty list
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no MPS found")
	})

	t.Run("add_remote_access_policy_rule_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{
			{Name: "test-mps"},
		}, nil)

		// Mock AddRemoteAccessPolicyRule to return an error
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, errors.New("policy rule error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add periodic remote access policy rule")
	})

	t.Run("environment_detection_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{
			{Name: "test-mps"},
		}, nil)

		// Mock AddRemoteAccessPolicyRule calls
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(0), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)

		// Mock GetRemoteAccessPolicies (after adding rules)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{
			{}, // periodic policy
			{}, // user-initiated policy
		}, nil)

		// Mock PutRemoteAccessPolicyAppliesToMPS calls
		mockWSMAN.EXPECT().PutRemoteAccessPolicyAppliesToMPS(gomock.Any()).Return(remoteaccess.Body{}, nil).Times(2)

		// Mock RequestStateChangeCIRA
		mockWSMAN.EXPECT().RequestStateChangeCIRA().Return(userinitiatedconnection.RequestStateChange_OUTPUT{}, nil)

		// Mock GetEnvironmentDetectionSettings to return an error
		mockWSMAN.EXPECT().GetEnvironmentDetectionSettings().Return(environmentdetection.EnvironmentDetectionSettingDataResponse{}, errors.New("env detection error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get environment detection settings")
	})

	t.Run("no_environment_detection_settings", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"auto-generated.com"}, // Environment detection will be auto-generated in Validate
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{
			{Name: "test-mps"},
		}, nil)

		// Mock AddRemoteAccessPolicyRule calls
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(0), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)

		// Mock GetRemoteAccessPolicies (after adding rules)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{
			{}, // periodic policy
			{}, // user-initiated policy
		}, nil)

		// Mock PutRemoteAccessPolicyAppliesToMPS calls
		mockWSMAN.EXPECT().PutRemoteAccessPolicyAppliesToMPS(gomock.Any()).Return(remoteaccess.Body{}, nil).Times(2)

		// Mock RequestStateChangeCIRA
		mockWSMAN.EXPECT().RequestStateChangeCIRA().Return(userinitiatedconnection.RequestStateChange_OUTPUT{}, nil)

		// Mock GetEnvironmentDetectionSettings - environment detection is always configured
		mockWSMAN.EXPECT().GetEnvironmentDetectionSettings().Return(environmentdetection.EnvironmentDetectionSettingDataResponse{
			ElementName:        "Environment Detection",
			InstanceID:         "env-id",
			DetectionAlgorithm: 1,
		}, nil)

		// Mock PutEnvironmentDetectionSettings
		mockWSMAN.EXPECT().PutEnvironmentDetectionSettings(gomock.Any()).Return(environmentdetection.EnvironmentDetectionSettingDataResponse{}, nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err) // Should succeed with auto-generated environment detection
	})

	t.Run("request_state_change_cira_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &CIRACmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					ControlMode: 1,
					Password:    "amt123",
					WSMan:       mockWSMAN,
				},
			},
			MPSPassword:          "mps123",
			MPSAddress:           "https://mps.example.com",
			MPSCert:              "test-cert",
			EnvironmentDetection: []string{"example.com"},
		}

		ctx := &commands.Context{
			AMTCommand: mockAMT,
		}

		// Mock clearCIRA operations (successful)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{}, nil)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{}, nil)

		// Mock AddTrustedRootCert
		mockWSMAN.EXPECT().AddTrustedRootCert("test-cert").Return("cert-handle", nil)

		// Mock AddMPS
		mockWSMAN.EXPECT().AddMPS("mps123", "https://mps.example.com", 4433).Return(remoteaccess.AddMpServerResponse{}, nil)

		// Mock GetMPSSAP (after adding MPS)
		mockWSMAN.EXPECT().GetMPSSAP().Return([]managementpresence.ManagementRemoteResponse{
			{Name: "test-mps"},
		}, nil)

		// Mock AddRemoteAccessPolicyRule calls
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(2), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)
		mockWSMAN.EXPECT().AddRemoteAccessPolicyRule(remoteaccess.Trigger(0), "test-mps").Return(remoteaccess.AddRemoteAccessPolicyRuleResponse{}, nil)

		// Mock GetRemoteAccessPolicies (after adding rules)
		mockWSMAN.EXPECT().GetRemoteAccessPolicies().Return([]remoteaccess.RemoteAccessPolicyAppliesToMPSResponse{
			{}, // periodic policy
			{}, // user-initiated policy
		}, nil)

		// Mock PutRemoteAccessPolicyAppliesToMPS calls
		mockWSMAN.EXPECT().PutRemoteAccessPolicyAppliesToMPS(gomock.Any()).Return(remoteaccess.Body{}, nil).Times(2)

		// Mock RequestStateChangeCIRA to return an error
		mockWSMAN.EXPECT().RequestStateChangeCIRA().Return(userinitiatedconnection.RequestStateChange_OUTPUT{}, errors.New("state change error"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable CIRA")
	})
}
