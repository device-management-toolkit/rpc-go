/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/timesynchronization"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/common"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// Helper function to add common time sync mocks
func addTimeSyncMocks(mockWSMan *mock.MockWSMANer) {
	// Mock GetLowAccuracyTimeSynch
	ta0 := time.Now().Unix()
	lowAccuracyResponse := timesynchronization.Response{
		Body: timesynchronization.Body{
			GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
				Ta0:         ta0,
				ReturnValue: 0,
			},
		},
	}
	mockWSMan.EXPECT().GetLowAccuracyTimeSynch().Return(lowAccuracyResponse, nil)

	// Mock SetHighAccuracyTimeSynch
	highAccuracyResponse := timesynchronization.Response{
		Body: timesynchronization.Body{
			SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
				ReturnValue: 0,
			},
		},
	}
	mockWSMan.EXPECT().SetHighAccuracyTimeSynch(ta0, gomock.Any(), gomock.Any()).Return(highAccuracyResponse, nil)
}

func TestTLSCmd_Structure(t *testing.T) {
	// Test that TLSCmd has the correct structure
	cmd := &TLSCmd{}

	// Test basic field access to ensure struct is correct
	cmd.Password = "test123"
	cmd.Mode = "Server"
	cmd.Delay = 5
	cmd.EAAddress = "https://ea.example.com"
	cmd.EAUsername = "testuser"
	cmd.EAPassword = "testpass"

	assert.Equal(t, "test123", cmd.Password)
	assert.Equal(t, "Server", cmd.Mode)
	assert.Equal(t, 5, cmd.Delay)
	assert.Equal(t, "https://ea.example.com", cmd.EAAddress)
	assert.Equal(t, "testuser", cmd.EAUsername)
	assert.Equal(t, "testpass", cmd.EAPassword)
}

func TestTLSCmd_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     *TLSCmd
		wantErr bool
	}{
		{
			name: "valid command with password",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				Mode:  "Server",
				Delay: 3,
			},
			wantErr: false,
		},
		{
			name: "valid Enterprise Assistant configuration",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
					EAAddress:  "https://ea.example.com",
					EAUsername: "testuser",
					EAPassword: "testpass",
				},
				Mode:  "Mutual",
				Delay: 5,
			},
			wantErr: false,
		},
		{
			name: "invalid - negative delay",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
				},
				Mode:  "Server",
				Delay: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid - incomplete EA configuration",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
					EAAddress:  "https://ea.example.com",
					EAUsername: "testuser",
					// Missing EAPassword
				},
				Mode: "Server",
			},
			wantErr: true,
		},
		{
			name: "invalid - bad EA URL",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
					EAAddress:  "invalid-url",
					EAUsername: "testuser",
					EAPassword: "testpass",
				},
				Mode: "Server",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTLSCmd_Run(t *testing.T) {
	tests := []struct {
		name          string
		cmd           *TLSCmd
		setupMocks    func(*mock.MockWSMANer)
		wantErr       bool
		expectedError string
	}{
		{
			name: "successful_TLS_disabled_mode",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				Mode:  "None",
				Delay: 0,
			},
			setupMocks: func(m *mock.MockWSMANer) {
				// Mock successful TLS configuration for disabled mode
				enumerateResp := tls.Response{
					Body: tls.Body{
						EnumerateResponse: common.EnumerateResponse{
							EnumerationContext: "test-context",
						},
					},
				}
				m.EXPECT().EnumerateTLSSettingData().Return(enumerateResp, nil)

				boolTrue := true
				pullResp := tls.Response{
					Body: tls.Body{
						PullResponse: tls.PullResponse{
							SettingDataItems: []tls.SettingDataResponse{
								{
									InstanceID:                    RemoteTLSInstanceId,
									ElementName:                   "Remote TLS",
									Enabled:                       true,
									AcceptNonSecureConnections:    false,
									MutualAuthentication:          false,
									NonSecureConnectionsSupported: &boolTrue,
								},
							},
						},
					},
				}
				m.EXPECT().PullTLSSettingData("test-context").Return(pullResp, nil)

				// Mock successful PUT operation to disable TLS
				m.EXPECT().PUTTLSSettings(RemoteTLSInstanceId, gomock.Any()).Return(tls.Response{}, nil)

				// Mock successful commit
				m.EXPECT().CommitChanges().Return(setupandconfiguration.Response{}, nil)

				// Mock PruneCerts calls
				m.EXPECT().GetConcreteDependencies().Return([]concrete.ConcreteDependency{}, nil)
				m.EXPECT().GetPublicKeyCerts().Return([]publickey.RefinedPublicKeyCertificateResponse{}, nil)
				m.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{}, nil)
				m.EXPECT().GetCredentialRelationships().Return(credential.Items{}, nil)
			},
			wantErr: false,
		},
		{
			name: "enumerate_TLS_settings_error",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				Mode:  "None",
				Delay: 0,
			},
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().EnumerateTLSSettingData().Return(tls.Response{}, errors.New("enumerate error"))
			},
			wantErr:       true,
			expectedError: "failed to enumerate TLS settings",
		},
		{
			name: "pull_TLS_settings_error",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				Mode:  "None",
				Delay: 0,
			},
			setupMocks: func(m *mock.MockWSMANer) {
				enumerateResp := tls.Response{
					Body: tls.Body{
						EnumerateResponse: common.EnumerateResponse{
							EnumerationContext: "test-context",
						},
					},
				}
				m.EXPECT().EnumerateTLSSettingData().Return(enumerateResp, nil)
				m.EXPECT().PullTLSSettingData("test-context").Return(tls.Response{}, errors.New("pull error"))
			},
			wantErr:       true,
			expectedError: "failed to pull TLS settings",
		},
		{
			name: "commit_changes_error",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				Mode:  "None",
				Delay: 0,
			},
			setupMocks: func(m *mock.MockWSMANer) {
				enumerateResp := tls.Response{
					Body: tls.Body{
						EnumerateResponse: common.EnumerateResponse{
							EnumerationContext: "test-context",
						},
					},
				}
				m.EXPECT().EnumerateTLSSettingData().Return(enumerateResp, nil)

				boolTrue := true
				pullResp := tls.Response{
					Body: tls.Body{
						PullResponse: tls.PullResponse{
							SettingDataItems: []tls.SettingDataResponse{
								{
									InstanceID:                    RemoteTLSInstanceId,
									ElementName:                   "Remote TLS",
									Enabled:                       false,
									AcceptNonSecureConnections:    false,
									MutualAuthentication:          false,
									NonSecureConnectionsSupported: &boolTrue,
								},
							},
						},
					},
				}
				m.EXPECT().PullTLSSettingData("test-context").Return(pullResp, nil)
				m.EXPECT().PUTTLSSettings(RemoteTLSInstanceId, gomock.Any()).Return(tls.Response{}, nil)
				m.EXPECT().CommitChanges().Return(setupandconfiguration.Response{}, errors.New("commit error"))
			},
			wantErr:       true,
			expectedError: "failed to commit TLS changes",
		},
		{
			name: "invalid_TLS_mode",
			cmd: &TLSCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				Mode:  "InvalidMode",
				Delay: 0,
			},
			setupMocks: func(m *mock.MockWSMANer) {
				// No mocks needed as validation should fail early
			},
			wantErr:       true,
			expectedError: "invalid TLS mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockWSMan := mock.NewMockWSMANer(ctrl)
			mockAMT := mock.NewMockInterface(ctrl)

			// Add time sync mocks for all tests
			if !tt.wantErr || (tt.wantErr && tt.expectedError != "invalid TLS mode") {
				addTimeSyncMocks(mockWSMan)
			}

			tt.setupMocks(mockWSMan)

			tt.cmd.WSMan = mockWSMan
			ctx := &commands.Context{
				AMTCommand: mockAMT,
			}

			err := tt.cmd.Run(ctx)

			if tt.wantErr {
				assert.Error(t, err)

				if tt.expectedError != "" {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("structure_validation", func(t *testing.T) {
		cmd := &TLSCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},

				EAAddress:  "https://ea.example.com",
				EAUsername: "testuser",
				EAPassword: "testpass",
			},
			Mode:  "Mutual",
			Delay: 5,
		}

		// Verify command has required fields
		assert.NotEmpty(t, cmd.Password)
		assert.NotEmpty(t, cmd.Mode)
		assert.Equal(t, 5, cmd.Delay)
		assert.NotEmpty(t, cmd.EAAddress)
		assert.NotEmpty(t, cmd.EAUsername)
		assert.NotEmpty(t, cmd.EAPassword)
	})
}

func TestParseTLSMode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected TLSMode
		wantErr  bool
	}{
		{"Server", "Server", TLSModeServer, false},
		{"ServerAndNonTLS", "ServerAndNonTLS", TLSModeServerAndNonTLS, false},
		{"Mutual", "Mutual", TLSModeMutual, false},
		{"MutualAndNonTLS", "MutualAndNonTLS", TLSModeMutualAndNonTLS, false},
		{"None", "None", TLSModeDisabled, false},
		{"Invalid", "Invalid", TLSModeServer, true},
		{"Empty", "", TLSModeServer, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTLSMode(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestDetermineTLSMode(t *testing.T) {
	tests := []struct {
		name        string
		mutualAuth  bool
		enabled     bool
		allowNonTLS bool
		expected    string
	}{
		{"Server only", false, true, false, TLSModeServerValue},
		{"Server and NonTLS", false, true, true, TLSModeServerAndNonTLSValue},
		{"Mutual only", true, true, false, TLSModeMutualValue},
		{"Mutual and NonTLS", true, true, true, TLSModeMutualAndNonTLSValue},
		{"Disabled", false, false, false, TLSModeDisabledValue},
		{"Disabled with flags", true, false, true, TLSModeDisabledValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetermineTLSMode(tt.mutualAuth, tt.enabled, tt.allowNonTLS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTLSMode_String(t *testing.T) {
	tests := []struct {
		mode     TLSMode
		expected string
	}{
		{TLSModeServer, TLSModeServerValue},
		{TLSModeServerAndNonTLS, TLSModeServerAndNonTLSValue},
		{TLSModeMutual, TLSModeMutualValue},
		{TLSModeMutualAndNonTLS, TLSModeMutualAndNonTLSValue},
		{TLSModeDisabled, TLSModeDisabledValue},
		{TLSMode(999), TLSModeUnknownValue}, // Invalid mode
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.mode.String())
		})
	}
}

func TestTLSModesToString(t *testing.T) {
	result := TLSModesToString()
	expected := "Server, ServerAndNonTLS, Mutual, MutualAndNonTLS, None"
	assert.Equal(t, expected, result)
}

func TestTLSCmd_generateKeyPair(t *testing.T) {
	tests := []struct {
		name       string
		setupMocks func(*mock.MockWSMANer)
		wantErr    bool
		wantHandle string
	}{
		{
			name: "successful_key_generation",
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().GenerateKeyPair(publickey.RSA, publickey.KeyLength(2048)).Return(publickey.Response{
					Body: publickey.Body{
						GenerateKeyPair_OUTPUT: publickey.GenerateKeyPair_OUTPUT{
							ReturnValue: 0,
							KeyPair: publickey.KeyPairResponse{
								ReferenceParameters: publickey.ReferenceParametersResponse{
									SelectorSet: publickey.SelectorSetResponse{
										Selectors: []publickey.SelectorResponse{
											{Text: "test-keypair-handle"},
										},
									},
								},
							},
						},
					},
				}, nil)
			},
			wantErr:    false,
			wantHandle: "test-keypair-handle",
		},
		{
			name: "wsman_error",
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().GenerateKeyPair(publickey.RSA, publickey.KeyLength(2048)).Return(publickey.Response{}, errors.New("wsman error"))
			},
			wantErr: true,
		},
		{
			name: "return_value_error",
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().GenerateKeyPair(publickey.RSA, publickey.KeyLength(2048)).Return(publickey.Response{
					Body: publickey.Body{
						GenerateKeyPair_OUTPUT: publickey.GenerateKeyPair_OUTPUT{
							ReturnValue: 1, // Non-zero return value indicates error
						},
					},
				}, nil)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockWSMan := mock.NewMockWSMANer(ctrl)
			tt.setupMocks(mockWSMan)

			cmd := &TLSCmd{}
			cmd.WSMan = mockWSMan

			handle, err := cmd.generateKeyPair()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				if tt.wantHandle != "" {
					assert.Equal(t, tt.wantHandle, handle)
				}
			}
		})
	}
}

func TestTLSCmd_getDERKey(t *testing.T) {
	tests := []struct {
		name       string
		handle     string
		setupMocks func(*mock.MockWSMANer)
		wantDER    string
		wantErr    bool
	}{
		{
			name:   "successful_der_key_retrieval",
			handle: "test-handle",
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{
					{
						InstanceID: "test-handle",
						DERKey:     "test-der-key",
					},
					{
						InstanceID: "other-handle",
						DERKey:     "other-der-key",
					},
				}, nil)
			},
			wantDER: "test-der-key",
			wantErr: false,
		},
		{
			name:   "wsman_error",
			handle: "test-handle",
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().GetPublicPrivateKeyPairs().Return(nil, errors.New("wsman error"))
			},
			wantErr: true,
		},
		{
			name:   "handle_not_found",
			handle: "missing-handle",
			setupMocks: func(m *mock.MockWSMANer) {
				m.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{
					{
						InstanceID: "other-handle",
						DERKey:     "other-der-key",
					},
				}, nil)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockWSMan := mock.NewMockWSMANer(ctrl)
			tt.setupMocks(mockWSMan)

			cmd := &TLSCmd{}
			cmd.WSMan = mockWSMan
			derKey, err := cmd.getDERKey(tt.handle)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantDER, derKey)
			}
		})
	}
}
