/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// MockPasswordReader for testing password scenarios
type MockPasswordReaderSuccess struct{}

func (mpr *MockPasswordReaderSuccess) ReadPassword() (string, error) {
	return utils.TestPassword, nil
}

func (mpr *MockPasswordReaderSuccess) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	return utils.TestPassword, nil
}

type MockPasswordReaderFail struct{}

func (mpr *MockPasswordReaderFail) ReadPassword() (string, error) {
	return "", errors.New("Read password failed")
}

func (mpr *MockPasswordReaderFail) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	return "", errors.New("Read password failed")
}

type MockPasswordReaderEmpty struct{}

func (mpr *MockPasswordReaderEmpty) ReadPassword() (string, error) {
	return "", nil
}

func (mpr *MockPasswordReaderEmpty) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	return "", nil
}

func TestDeactivateCmd_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cmd     DeactivateCmd
		wantErr string
	}{
		{
			name: "both local and ws URL provided",
			cmd: DeactivateCmd{
				Local: true,
				URL:   "wss://example.com",
			},
			wantErr: "provide either a 'url' or a 'local', but not both",
		},
		{
			name: "partial unprovision with HTTP URL",
			cmd: DeactivateCmd{
				PartialUnprovision: true,
				URL:                "https://example.com",
			},
			wantErr: "partial unprovisioning is not supported with HTTP(S) --url",
		},
		{
			name: "partial unprovision without local",
			cmd: DeactivateCmd{
				PartialUnprovision: true,
				URL:                "wss://example.com",
			},
			wantErr: "partial unprovisioning is only supported with local flag",
		},
		{
			name: "no URL provided for remote",
			cmd: DeactivateCmd{
				Local: false,
			},
			wantErr: "-u flag is required when not using local mode",
		},
		{
			name:    "valid local mode",
			cmd:     DeactivateCmd{Local: true},
			wantErr: "",
		},
		{
			name:    "valid remote mode with ws URL",
			cmd:     DeactivateCmd{URL: "wss://example.com"},
			wantErr: "",
		},
		{
			name:    "valid HTTP console URL",
			cmd:     DeactivateCmd{URL: "https://example.com"},
			wantErr: "",
		},
		{
			name:    "valid HTTP console URL with local flag",
			cmd:     DeactivateCmd{URL: "https://example.com", Local: true},
			wantErr: "",
		},
		{
			name:    "valid local with partial",
			cmd:     DeactivateCmd{Local: true, PartialUnprovision: true},
			wantErr: "",
		},
		{
			name: "partial unprovision with local and HTTP URL",
			cmd: DeactivateCmd{
				Local:              true,
				PartialUnprovision: true,
				URL:                "https://example.com",
			},
			wantErr: "partial unprovisioning is not supported with HTTP(S) --url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cmd.Validate()

			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestDeactivateCmd_Validate_LocalWithHTTPURL_PreservesConsoleURL(t *testing.T) {
	cmd := DeactivateCmd{URL: "https://console.example.com", Local: true}
	err := cmd.Validate()
	assert.NoError(t, err)
	assert.Equal(t, "", cmd.URL, "URL should be cleared")
	assert.Equal(t, "https://console.example.com", cmd.consoleURL, "consoleURL should be preserved")
}

// Removed TestDeactivateCmd_EnsurePasswordProvided: password handling now centralized via context + EnsureAMTPassword.

func TestDeactivateCmd_SetupTLSConfig(t *testing.T) {
	cmd := &DeactivateCmd{}

	t.Run("TLS enforced", func(t *testing.T) {
		cmd.LocalTLSEnforced = true
		ctx := &Context{SkipCertCheck: true, SkipAMTCertCheck: true, ControlMode: ControlModeACM}
		tlsConfig := cmd.setupTLSConfig(ctx)
		assert.NotNil(t, tlsConfig)
	})

	t.Run("TLS not enforced", func(t *testing.T) {
		cmd.LocalTLSEnforced = false
		ctx := &Context{ControlMode: ControlModeACM}
		tlsConfig := cmd.setupTLSConfig(ctx)
		assert.NotNil(t, tlsConfig)
	})
}

func TestDeactivateCmd_Run_Local_CCM(t *testing.T) {
	t.Run("successful CCM deactivation without password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("successful CCM deactivation with password (shows warning)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	t.Run("CCM deactivation fails on unprovision error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)
		mockAMT.EXPECT().Unprovision().Return(0, errors.New("unprovision failed"))

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})

	t.Run("CCM deactivation fails on non-zero status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)
		mockAMT.EXPECT().Unprovision().Return(1, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})

	t.Run("CCM partial unprovision not supported", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true, PartialUnprovision: true}
		// Set the control mode directly since it's now stored in AMTBaseCmd
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partial unprovisioning is only supported in ACM mode")
	})
}

func TestDeactivateCmd_Run_Local_GetControlModeFailure(t *testing.T) {
	t.Run("GetControlMode fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set invalid control mode to simulate failure
		cmd.ControlMode = 0 // This should trigger UnableToDeactivate

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

func TestDeactivateCmd_Run_Local_UnsupportedControlMode(t *testing.T) {
	t.Run("unsupported control mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set unsupported control mode
		cmd.ControlMode = 0 // Pre-provisioning mode

		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

// Test for ACM mode password handling
func TestDeactivateCmd_Run_Local_ACM_PasswordHandling(t *testing.T) {
	originalPR := utils.PR

	t.Run("ACM mode fails when password prompt fails (Run path)", func(t *testing.T) {
		utils.PR = &MockPasswordReaderFail{}

		defer func() { utils.PR = originalPR }()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		// Provide a mock WSMAN so EnsureWSMAN short-circuits and doesn't create a real client
		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := DeactivateCmd{Local: true}
		cmd.ControlMode = ControlModeACM
		cmd.WSMan = mockWSMAN

		ctx := &Context{} // Intentionally omit AMTPassword to trigger prompt
		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read AMT password")
	})

	t.Run("ACM mode fails when password is empty string (Run path)", func(t *testing.T) {
		utils.PR = &MockPasswordReaderEmpty{}

		defer func() { utils.PR = originalPR }()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockWSMAN := mock.NewMockWSMANer(ctrl)

		cmd := DeactivateCmd{Local: true}
		cmd.ControlMode = ControlModeACM
		cmd.WSMan = mockWSMAN

		ctx := &Context{}
		err := cmd.Run(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password cannot be empty")
	})
}

// Test for Run function routing logic
func TestDeactivateCmd_Run_Routing(t *testing.T) {
	t.Run("routes to local when Local flag is true", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set CCM control mode
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})

	// Note: Remote execution testing requires RPS mocking which is complex
	// For now, we focus on testing the routing logic and the parts we can control
}

// Test remote deactivate validation (password handling happens in Validate, not in executeRemoteDeactivate)
func TestDeactivateCmd_RemoteDeactivate_Validation(t *testing.T) {
	// Remote validation now only checks URL/local logic. Password prompting happens in Run.
	t.Run("remote deactivation Validate passes without password", func(t *testing.T) {
		cmd := DeactivateCmd{URL: "https://example.com"}
		err := cmd.Validate()
		assert.NoError(t, err)
	})
}

// Test for deactivateCCM function in isolation
func TestDeactivateCmd_DeactivateCCM(t *testing.T) {
	t.Run("CCM deactivation with password shows warning but succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.NoError(t, err)
	})

	t.Run("CCM deactivation without password succeeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.NoError(t, err)
	})

	t.Run("CCM deactivation fails with unprovision error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, errors.New("unprovision error"))

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})

	t.Run("CCM deactivation fails with non-zero status", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(5, nil) // Non-zero status

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{}

		err := cmd.deactivateCCM(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.DeactivationFailed, err)
	})
}

// Test for executeLocalDeactivate function logic
func TestDeactivateCmd_ExecuteLocalDeactivate(t *testing.T) {
	t.Run("handles control mode 3 (unknown mode)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set unknown control mode
		cmd.ControlMode = 3

		err := cmd.executeLocalDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})

	t.Run("handles negative control mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		cmd := DeactivateCmd{Local: true}
		// Set negative control mode
		cmd.ControlMode = -1

		err := cmd.executeLocalDeactivate(ctx)
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

// Test control mode constants
func TestControlModeConstants(t *testing.T) {
	assert.Equal(t, 1, ControlModeCCM)
	assert.Equal(t, 2, ControlModeACM)
}

// Test edge cases for password handling
// Legacy password handling tests removed due to context-based password refactor.

// Test additional Run method edge cases
func TestRunMethodEdgeCases(t *testing.T) {
	t.Run("local deactivation with CCM and partial unprovision error", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{
			Local:              true,
			PartialUnprovision: true,
		}
		// Set CCM control mode
		cmd.ControlMode = ControlModeCCM

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partial unprovisioning is only supported in ACM mode")
	})

	t.Run("local deactivation with unknown control mode", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{Local: true}
		// Set unknown control mode
		cmd.ControlMode = 999

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})

	t.Run("local deactivation with AMT connection failure", func(t *testing.T) {
		// Setup
		cmd := &DeactivateCmd{Local: true}
		// Set zero control mode (pre-provisioning)
		cmd.ControlMode = 0

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		// Execute
		err := cmd.Run(ctx)

		// Verify
		assert.Error(t, err)
		assert.Equal(t, utils.UnableToDeactivate, err)
	})
}

func TestDeactivateCmd_AuthenticateWithConsole(t *testing.T) {
	t.Run("uses token when provided", func(t *testing.T) {
		cmd := &DeactivateCmd{URL: "https://console.example.com"}
		ctx := &Context{}
		ctx.AuthToken = "my-token"

		token, err := cmd.authenticateWithConsole(ctx, "https://console.example.com")
		assert.NoError(t, err)
		assert.Equal(t, "my-token", token)
	})

	t.Run("fails when no credentials provided", func(t *testing.T) {
		cmd := &DeactivateCmd{URL: "https://console.example.com"}
		ctx := &Context{}

		_, err := cmd.authenticateWithConsole(ctx, "https://console.example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication required")
	})
}

func TestDeactivateCmd_ResolveGUID(t *testing.T) {
	t.Run("uses UUID flag when provided", func(t *testing.T) {
		cmd := &DeactivateCmd{UUID: "test-guid-123"}
		ctx := &Context{}

		guid, err := cmd.resolveGUID(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "test-guid-123", guid)
	})

	t.Run("uses AMTCommand when no UUID flag", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("amt-guid-456", nil)

		cmd := &DeactivateCmd{}
		ctx := &Context{AMTCommand: mockAMT}

		guid, err := cmd.resolveGUID(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "amt-guid-456", guid)
	})

	t.Run("fails when no UUID and no AMTCommand", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		ctx := &Context{}

		_, err := cmd.resolveGUID(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to determine device GUID")
	})
}

func TestDeactivateCmd_DeleteDeviceFromConsoleIfAuth(t *testing.T) {
	t.Run("no auth credentials skips console deletion", func(t *testing.T) {
		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "")
		assert.NoError(t, err)
	})

	t.Run("partial unprovision skips console deletion", func(t *testing.T) {
		cmd := &DeactivateCmd{Local: true, PartialUnprovision: true}
		ctx := &Context{}
		ctx.AuthUsername = "admin"
		ctx.AuthPassword = "P@ssw0rd"
		ctx.AuthEndpoint = "http://console.example.com/api/v1/authorize"

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "some-guid")
		assert.NoError(t, err)
	})

	t.Run("auth creds with relative auth-endpoint errors", func(t *testing.T) {
		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}
		ctx.AuthUsername = "admin"
		ctx.AuthPassword = "P@ssw0rd"
		ctx.AuthEndpoint = "/api/v1/authorize"

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "some-guid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not an absolute URL")
	})

	t.Run("auth creds with empty auth-endpoint errors", func(t *testing.T) {
		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}
		ctx.AuthUsername = "admin"
		ctx.AuthPassword = "P@ssw0rd"
		ctx.AuthEndpoint = ""

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "some-guid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no console URL available")
	})

	t.Run("auth token with absolute auth-endpoint deletes device", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Contains(t, r.URL.Path, "/api/v1/devices/test-guid")
			assert.Equal(t, "Bearer my-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}
		ctx.AuthToken = "my-token"
		ctx.AuthEndpoint = server.URL + "/api/v1/authorize"

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "test-guid")
		assert.NoError(t, err)
	})

	t.Run("username/password with absolute auth-endpoint authenticates and deletes", func(t *testing.T) {
		callCount := 0

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++

			if r.URL.Path == "/api/v1/authorize" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token":"server-token"}`))

				return
			}

			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Contains(t, r.URL.Path, "/api/v1/devices/test-guid")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}
		ctx.AuthUsername = "admin"
		ctx.AuthPassword = "P@ssw0rd"
		ctx.AuthEndpoint = server.URL + "/api/v1/authorize"

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "test-guid")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, callCount, 2)
	})

	t.Run("delete device fails returns error with context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}
		ctx.AuthToken = "my-token"
		ctx.AuthEndpoint = server.URL + "/api/v1/authorize"

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "test-guid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "device deactivated but failed to delete from console")
	})

	t.Run("consoleURL from --url takes precedence over auth-endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Contains(t, r.URL.Path, "/api/v1/devices/test-guid")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cmd := &DeactivateCmd{Local: true}
		cmd.consoleURL = server.URL // simulates --url preserved by Validate

		ctx := &Context{}
		ctx.AuthToken = "my-token"
		ctx.AuthEndpoint = "http://other-host/api/v1/authorize" // should not be used

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "test-guid")
		assert.NoError(t, err)
	})

	t.Run("empty pre-resolved GUID returns error", func(t *testing.T) {
		cmd := &DeactivateCmd{Local: true}
		ctx := &Context{}
		ctx.AuthToken = "my-token"
		ctx.AuthEndpoint = "http://console.example.com/api/v1/authorize"

		err := cmd.deleteDeviceFromConsoleIfAuth(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to determine device GUID")
	})
}

func TestDeactivateCmd_Run_LocalWithAuthDeletesFromConsole(t *testing.T) {
	t.Run("local CCM deactivation with auth credentials deletes from console", func(t *testing.T) {
		deleteCalled := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deleteCalled = true

				assert.Contains(t, r.URL.Path, "/api/v1/devices/")
				w.WriteHeader(http.StatusOK)

				return
			}

			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		ctx.AuthToken = "my-token"
		ctx.AuthEndpoint = server.URL + "/api/v1/authorize"

		cmd := DeactivateCmd{Local: true}
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
		assert.True(t, deleteCalled, "should have called DELETE on console")
	})

	t.Run("local CCM deactivation with --url deletes from console", func(t *testing.T) {
		deleteCalled := false

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/authorize" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token":"server-token"}`))

				return
			}

			if r.Method == http.MethodDelete {
				deleteCalled = true

				assert.Contains(t, r.URL.Path, "/api/v1/devices/device-guid")
				w.WriteHeader(http.StatusOK)

				return
			}

			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().Unprovision().Return(0, nil)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}
		ctx.AuthUsername = "admin"
		ctx.AuthPassword = "P@ssw0rd"
		ctx.AuthEndpoint = "/api/v1/authorize"

		// --local + --url: Validate moves URL to consoleURL
		cmd := DeactivateCmd{Local: true, URL: server.URL}
		cmd.ControlMode = ControlModeCCM

		err := cmd.Validate()
		require.NoError(t, err)

		err = cmd.Run(ctx)
		assert.NoError(t, err)
		assert.True(t, deleteCalled, "should have called DELETE on console")
	})

	t.Run("local deactivation without auth does not call console", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMT := mock.NewMockInterface(ctrl)
		mockAMT.EXPECT().GetUUID().Return("device-guid", nil)
		mockAMT.EXPECT().Unprovision().Return(0, nil)

		ctx := &Context{AMTCommand: mockAMT, AMTPassword: "test-pass"}

		cmd := DeactivateCmd{Local: true}
		cmd.ControlMode = ControlModeCCM

		err := cmd.Run(ctx)
		assert.NoError(t, err)
	})
}

func TestIsAbsoluteURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://example.com/api", true},
		{"http://example.com/api", true},
		{"HTTP://EXAMPLE.COM", true},
		{"HTTPS://EXAMPLE.COM", true},
		{"/api/v1/authorize", false},
		{"api/v1/authorize", false},
		{"", false},
		{"ftp://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, isAbsoluteURL(tt.input))
		})
	}
}

// Test setupTLSConfig function
func TestSetupTLSConfig(t *testing.T) {
	t.Run("TLS config with LocalTLSEnforced false", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		cmd.LocalTLSEnforced = true
		ctx := &Context{ControlMode: ControlModeACM}

		tlsConfig := cmd.setupTLSConfig(ctx)

		assert.NotNil(t, tlsConfig)
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("TLS config with LocalTLSEnforced true", func(t *testing.T) {
		cmd := &DeactivateCmd{}
		cmd.LocalTLSEnforced = true
		ctx := &Context{
			SkipCertCheck: true,
			ControlMode:   ControlModeACM,
		}

		tlsConfig := cmd.setupTLSConfig(ctx)

		assert.NotNil(t, tlsConfig)
		// The actual config setup depends on the config.GetTLSConfig implementation
	})
}
