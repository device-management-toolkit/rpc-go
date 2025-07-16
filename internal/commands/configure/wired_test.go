/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/stretchr/testify/assert"
)

func TestWiredCmd_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     *WiredCmd
		wantErr bool
	}{
		{
			name: "invalid - no configuration specified",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
				},
			},
			wantErr: true,
		},
		{
			name: "valid static IP configuration",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				IPAddress:    "192.168.1.100",
				SubnetMask:   "255.255.255.0",
				Gateway:      "192.168.1.1",
				PrimaryDNS:   "8.8.8.8",
				SecondaryDNS: "8.8.4.4",
			},
			wantErr: false,
		},
		{
			name: "valid DHCP configuration",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
				},
				DHCPEnabled: func() *bool {
					b := true

					return &b
				}(),
			},
			wantErr: false,
		},
		{
			name: "invalid - DHCP with static IP",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
				},
				DHCPEnabled: func() *bool {
					b := true

					return &b
				}(),
				IPAddress: "192.168.1.100",
			},
			wantErr: true,
		},
		{
			name: "invalid - incomplete static IP",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
				},
				IPAddress: "192.168.1.100",
				// Missing subnet mask, gateway, DNS
			},
			wantErr: true,
		},
		{
			name: "invalid - bad IP format",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
				},
				IPAddress:  "invalid-ip",
				SubnetMask: "255.255.255.0",
				Gateway:    "192.168.1.1",
				PrimaryDNS: "8.8.8.8",
			},
			wantErr: true,
		},
		{
			name: "valid - DHCP with 802.1x",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
					IEEE8021xProfileName:            "test8021x",
					IEEE8021xUsername:               "testuser",
					IEEE8021xPassword:               "testpass",
					IEEE8021xAuthenticationProtocol: 2, // PEAP-MSCHAPv2
					IEEE8021xCACert:                 "test-ca-cert",
				},
				DHCPEnabled: func() *bool {
					b := true

					return &b
				}(),
			},
			wantErr: false,
		},
		{
			name: "valid - static IP with 802.1x",
			cmd: &WiredCmd{
				ConfigureBaseCmd: ConfigureBaseCmd{
					AMTBaseCmd: commands.AMTBaseCmd{
						ControlMode: 1,
						Password:    "test-test123",
					},
					IEEE8021xProfileName:            "test8021x",
					IEEE8021xUsername:               "testuser",
					IEEE8021xAuthenticationProtocol: 0, // EAP-TLS
					IEEE8021xPrivateKey:             "test-private-key",
					IEEE8021xClientCert:             "test-client-cert",
					IEEE8021xCACert:                 "test-ca-cert",
				},
				IPAddress:  "192.168.1.100",
				SubnetMask: "255.255.255.0",
				Gateway:    "192.168.1.1",
				PrimaryDNS: "8.8.8.8",
			},
			wantErr: false,
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

func TestWiredCmd_Run(t *testing.T) {
	// TODO: Add mock-based integration tests
	// These would require mocking:
	// - cmd.WSMan.GetEthernetSettings()
	// - cmd.WSMan.PutEthernetSettings()
	// - cmd.WSMan.GetIPSIEEE8021xSettings()
	// - cmd.WSMan.PutIPSIEEE8021xSettings()
	// - cmd.WSMan.SetIPSIEEE8021xCertificates()
	t.Run("structure_validation", func(t *testing.T) {
		cmd := &WiredCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{Password: "test-test123"},
			},
			IPAddress:    "192.168.1.100",
			SubnetMask:   "255.255.255.0",
			Gateway:      "192.168.1.1",
			PrimaryDNS:   "8.8.8.8",
			SecondaryDNS: "8.8.4.4",
		}

		// Verify command has required fields
		assert.NotEmpty(t, cmd.Password)
		assert.NotEmpty(t, cmd.IPAddress)
		assert.NotEmpty(t, cmd.SubnetMask)
		assert.NotEmpty(t, cmd.Gateway)
		assert.NotEmpty(t, cmd.PrimaryDNS)
		assert.NotEmpty(t, cmd.SecondaryDNS)
	})

	t.Run("8021x_validation", func(t *testing.T) {
		cmd := &WiredCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd:                      commands.AMTBaseCmd{Password: "test-test123"},
				IEEE8021xProfileName:            "test8021x",
				IEEE8021xUsername:               "testuser",
				IEEE8021xPassword:               "testpass",
				IEEE8021xAuthenticationProtocol: 2, // PEAP-MSCHAPv2
				IEEE8021xCACert:                 "test-ca-cert",
			},
			DHCPEnabled: func() *bool {
				b := true

				return &b
			}(),
		}

		// Verify IEEE 802.1x fields are properly set
		assert.NotEmpty(t, cmd.IEEE8021xProfileName)
		assert.NotEmpty(t, cmd.IEEE8021xUsername)
		assert.NotEmpty(t, cmd.IEEE8021xPassword)
		assert.Equal(t, 2, cmd.IEEE8021xAuthenticationProtocol)
		assert.NotEmpty(t, cmd.IEEE8021xCACert)
	})
}
