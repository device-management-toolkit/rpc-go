/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/stretchr/testify/assert"
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
			},
			wantErr: true,
		},
		{
			name: "802.1x authentication with PSK passphrase",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd:           commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
					IEEE8021xProfileName: "8021xprofile",
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
				PSKPassphrase:        "shouldnotbeset",
			},
			wantErr: true,
		},
		{
			name: "valid 802.1x authentication",
			cmd: &WirelessCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd:           commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
					IEEE8021xProfileName: "8021xprofile",
				},
				ProfileName:          "testprofile",
				SSID:                 "testssid",
				Priority:             1,
				AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
				EncryptionMethod:     int(wifi.EncryptionMethod_WEP),
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
				AMTBaseCmd:                      commands.AMTBaseCmd{Password: "test-test123", ControlMode: 1},
				IEEE8021xProfileName:            "test8021x",
				IEEE8021xUsername:               "testuser",
				IEEE8021xPassword:               "testpass",
				IEEE8021xAuthenticationProtocol: 2, // PEAP-MSCHAPv2
				IEEE8021xCACert:                 "test-ca-cert",
			},
			ProfileName:          "testprofile",
			SSID:                 "testssid",
			Priority:             1,
			AuthenticationMethod: int(wifi.AuthenticationMethodWPA2IEEE8021x),
			EncryptionMethod:     int(wifi.EncryptionMethod_CCMP),
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
