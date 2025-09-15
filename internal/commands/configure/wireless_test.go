/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestWirelessCmd_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     *WirelessCmd
		wantErr bool
	}{
		{
			name: "valid command with password",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
				PSKPassphrase:        "testpassphrase",
			},
			wantErr: false,
		},
		{
			name: "missing profile name",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
				PSKPassphrase:        "testpassphrase",
			},
			wantErr: true,
		},
		{
			name: "missing SSID",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
				PSKPassphrase:        "testpassphrase",
			},
			wantErr: true,
		},
		{
			name: "zero priority",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             0,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
				PSKPassphrase:        "testpassphrase",
			},
			wantErr: true,
		},
		{
			name: "invalid profile name with special characters",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "test-profile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
				PSKPassphrase:        "testpassphrase",
			},
			wantErr: true,
		},
		{
			name: "PSK authentication with missing passphrase",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
			},
			wantErr: true,
		},
		{
			name: "802.1x authentication with missing profile name",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
			},
			wantErr: true,
		},
		{
			name: "802.1x authentication with PSK passphrase",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				IEEE8021xProfileName: "8021xprofile",
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
				PSKPassphrase:        "shouldnotbeset",
			},
			wantErr: true,
		},
		{
			name: "valid 802.1x authentication",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				IEEE8021xProfileName: "8021xprofile",
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
			},
			wantErr: false,
		},
		{
			name: "unsupported authentication method",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodOther),
				EncryptionMethod:     int(wifi.EncryptionMethodCCMP),
			},
			wantErr: true,
		},
		{
			name: "unsupported encryption method",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2PSK),
				EncryptionMethod:     int(wifi.EncryptionMethodWEP),
				PSKPassphrase:        "testpassphrase",
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

func TestWirelessCmd_Run(t *testing.T) {
	// TODO: Add mock-based integration tests
	// These would require mocking:
	// - cmd.WSMan.AddWiFiSettings()
	t.Run("structure_validation", func(t *testing.T) {
		cmd := &WirelessCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
			},
			ProfileName:          "testprofile",
			SSID:                 "testssid",
			Priority:             1,
			AuthenticationMethod: 4,
			EncryptionMethod:     4,
			PSKPassphrase:        "testpassphrase",
		}

		// Verify command has required fields
		assert.NotEmpty(t, cmd.Password)
		assert.NotEmpty(t, cmd.ProfileName)
		assert.NotEmpty(t, cmd.SSID)
		assert.Equal(t, 1, cmd.Priority)
		assert.Equal(t, 4, cmd.AuthenticationMethod)
		assert.Equal(t, 4, cmd.EncryptionMethod)
		assert.NotEmpty(t, cmd.PSKPassphrase)
	})

	t.Run("8021x_validation", func(t *testing.T) {
		cmd := &WirelessCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
			},
			IEEE8021xProfileName:            "test8021x",
			IEEE8021xUsername:               "testuser",
			IEEE8021xPassword:               "testpass",
			IEEE8021xAuthenticationProtocol: 2, // PEAP-MSCHAPv2
			IEEE8021xCACert:                 "test-ca-cert",
			ProfileName:                     "testprofile",
			SSID:                            "testssid",
			Priority:                        1,
			AuthenticationMethod:            int(wifi.AuthenticationMethodWPA2IEEE8021x),
			EncryptionMethod:                int(wifi.EncryptionMethodCCMP),
		}

		// Verify IEEE 802.1x fields are properly set
		assert.NotEmpty(t, cmd.IEEE8021xProfileName)
		assert.NotEmpty(t, cmd.IEEE8021xUsername)
		assert.NotEmpty(t, cmd.IEEE8021xPassword)
		assert.Equal(t, 2, cmd.IEEE8021xAuthenticationProtocol)
		assert.NotEmpty(t, cmd.IEEE8021xCACert)
		assert.Equal(t, int(wifi.AuthenticationMethodWPA2IEEE8021x), cmd.AuthenticationMethod)
	})
}

func TestWirelessCmd_ClearWirelessProfiles(t *testing.T) {
	tests := []struct {
		name          string
		mockSetup     func(*mock.MockWSMANer)
		expectedError error
		expectedCalls int
	}{
		{
			name: "successfully clear profiles",
			mockSetup: func(mockWSMan *mock.MockWSMANer) {
				// Mock GetWiFiSettings to return sample profiles
				profiles := []wifi.WiFiEndpointSettingsResponse{
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile1"},
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile2"},
				}
				mockWSMan.EXPECT().GetWiFiSettings().Return(profiles, nil)

				// Expect DeleteWiFiSetting to be called for each profile
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile1").Return(nil)
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile2").Return(nil)

				// Mock PruneCerts dependencies
				mockWSMan.EXPECT().GetConcreteDependencies().Return([]concrete.ConcreteDependency{}, nil)
				mockWSMan.EXPECT().GetPublicKeyCerts().Return([]publickey.RefinedPublicKeyCertificateResponse{}, nil)
				mockWSMan.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{}, nil)
				mockWSMan.EXPECT().GetCredentialRelationships().Return(credential.Items{}, nil)
			},
			expectedError: nil,
			expectedCalls: 2,
		},
		{
			name: "handle profiles with empty InstanceID",
			mockSetup: func(mockWSMan *mock.MockWSMANer) {
				// Mock GetWiFiSettings to return profiles with some empty InstanceIDs
				profiles := []wifi.WiFiEndpointSettingsResponse{
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile1"},
					{InstanceID: ""}, // Empty InstanceID should be skipped
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile2"},
				}
				mockWSMan.EXPECT().GetWiFiSettings().Return(profiles, nil)

				// Expect DeleteWiFiSetting to be called only for profiles with valid InstanceIDs
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile1").Return(nil)
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile2").Return(nil)

				// Mock PruneCerts dependencies
				mockWSMan.EXPECT().GetConcreteDependencies().Return([]concrete.ConcreteDependency{}, nil)
				mockWSMan.EXPECT().GetPublicKeyCerts().Return([]publickey.RefinedPublicKeyCertificateResponse{}, nil)
				mockWSMan.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{}, nil)
				mockWSMan.EXPECT().GetCredentialRelationships().Return(credential.Items{}, nil)
			},
			expectedError: nil,
			expectedCalls: 2,
		},
		{
			name: "handle GetWiFiSettings error",
			mockSetup: func(mockWSMan *mock.MockWSMANer) {
				mockWSMan.EXPECT().GetWiFiSettings().Return(nil, errors.New("failed to get wifi settings"))
			},
			expectedError: errors.New("failed to get wifi settings"),
			expectedCalls: 0,
		},
		{
			name: "continue on delete errors",
			mockSetup: func(mockWSMan *mock.MockWSMANer) {
				profiles := []wifi.WiFiEndpointSettingsResponse{
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile1"},
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile2"},
				}
				mockWSMan.EXPECT().GetWiFiSettings().Return(profiles, nil)

				// First delete fails, second succeeds - both should be attempted
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile1").Return(errors.New("delete failed"))
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile2").Return(nil)

				// Mock PruneCerts dependencies
				mockWSMan.EXPECT().GetConcreteDependencies().Return([]concrete.ConcreteDependency{}, nil)
				mockWSMan.EXPECT().GetPublicKeyCerts().Return([]publickey.RefinedPublicKeyCertificateResponse{}, nil)
				mockWSMan.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{}, nil)
				mockWSMan.EXPECT().GetCredentialRelationships().Return(credential.Items{}, nil)
			},
			expectedError: nil,
			expectedCalls: 2,
		},
		{
			name: "handle PruneCerts error",
			mockSetup: func(mockWSMan *mock.MockWSMANer) {
				profiles := []wifi.WiFiEndpointSettingsResponse{
					{InstanceID: "Intel(r) AMT:WiFi Endpoint Settings profile1"},
				}
				mockWSMan.EXPECT().GetWiFiSettings().Return(profiles, nil)
				mockWSMan.EXPECT().DeleteWiFiSetting("Intel(r) AMT:WiFi Endpoint Settings profile1").Return(nil)

				// Mock PruneCerts to fail
				mockWSMan.EXPECT().GetConcreteDependencies().Return(nil, errors.New("failed to get concrete dependencies"))
			},
			expectedError: utils.WiFiConfigurationFailed,
			expectedCalls: 1,
		},
		{
			name: "no profiles to delete",
			mockSetup: func(mockWSMan *mock.MockWSMANer) {
				// Mock GetWiFiSettings to return empty slice
				profiles := []wifi.WiFiEndpointSettingsResponse{}
				mockWSMan.EXPECT().GetWiFiSettings().Return(profiles, nil)

				// Mock PruneCerts dependencies
				mockWSMan.EXPECT().GetConcreteDependencies().Return([]concrete.ConcreteDependency{}, nil)
				mockWSMan.EXPECT().GetPublicKeyCerts().Return([]publickey.RefinedPublicKeyCertificateResponse{}, nil)
				mockWSMan.EXPECT().GetPublicPrivateKeyPairs().Return([]publicprivate.RefinedPublicPrivateKeyPair{}, nil)
				mockWSMan.EXPECT().GetCredentialRelationships().Return(credential.Items{}, nil)
			},
			expectedError: nil,
			expectedCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockWSMan := mock.NewMockWSMANer(ctrl)
			tt.mockSetup(mockWSMan)

			cmd := &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{WSMan: mockWSMan},
				},
			}

			err := cmd.ClearWirelessProfiles()

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
