/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestEnableWifiPortCmd_Structure(t *testing.T) {
	cmd := &EnableWifiCmd{}

	// Verify struct embeds ConfigureBaseCmd
	assert.IsType(t, ConfigureBaseCmd{}, cmd.ConfigureBaseCmd)
}

func TestEnableWifiPortCmd_Run(t *testing.T) {
	t.Run("successful_wifi_port_enable", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi with sync and sharing enabled
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(nil)

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("enable_wifi_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi to return an error
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(errors.New("wifi enable failed"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable WiFi port")
		assert.Contains(t, err.Error(), "wifi enable failed")
	})

	t.Run("wsman_connection_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi to return a connection error
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(errors.New("connection timeout"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable WiFi port")
		assert.Contains(t, err.Error(), "connection timeout")
	})

	t.Run("wsman_authentication_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi to return an authentication error
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(errors.New("authentication failed"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable WiFi port")
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("nil_wsman_interface", func(t *testing.T) {
		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: nil, // Nil WSMAN interface
				},
			},
		}

		ctx := &commands.Context{}

		// This should panic or return an error when trying to call EnableWiFi on nil
		assert.Panics(t, func() {
			cmd.Run(ctx)
		})
	})

	t.Run("nil_context", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		// Mock EnableWiFi - context is not used in this command
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(nil)

		err := cmd.Run(nil)    // Nil context
		assert.NoError(t, err) // Should still work as context is not used
	})

	t.Run("multiple_consecutive_calls", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi to be called multiple times
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(nil).Times(3)

		// Call the command multiple times
		err1 := cmd.Run(ctx)
		assert.NoError(t, err1)

		err2 := cmd.Run(ctx)
		assert.NoError(t, err2)

		err3 := cmd.Run(ctx)
		assert.NoError(t, err3)
	})

	t.Run("wifi_not_available_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi to return a WiFi not available error
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(errors.New("WiFi hardware not available"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable WiFi port")
		assert.Contains(t, err.Error(), "WiFi hardware not available")
	})

	t.Run("amt_not_provisioned_error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := &EnableWifiCmd{
			ConfigureBaseCmd: ConfigureBaseCmd{
				AMTBaseCmd: commands.AMTBaseCmd{
					WSMan: mockWSMAN,
				},
			},
		}

		ctx := &commands.Context{
			AMTPassword: "test-pass",
		}

		// Mock EnableWiFi to return an AMT not provisioned error
		mockWSMAN.EXPECT().EnableWiFi(true, true).Return(errors.New("AMT not provisioned"))

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enable WiFi port")
		assert.Contains(t, err.Error(), "AMT not provisioned")
	})

	t.Run("structure_validation", func(t *testing.T) {
		cmd := &EnableWifiCmd{}

		// Test that the struct has the expected fields
		assert.NotNil(t, cmd)
		assert.IsType(t, ConfigureBaseCmd{}, cmd.ConfigureBaseCmd)
	})
}
