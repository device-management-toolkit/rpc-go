/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	amttls "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
	"github.com/device-management-toolkit/rpc-go/v2/internal/device"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/internal/profile"
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
			name: "conflicting local and remote flags (ws/wss) should fail",
			cmd: ActivateCmd{
				Local:   true,
				URL:     "wss://192.168.1.1/activate",
				Profile: "test-profile",
			},
			wantErr: true,
		},
		{
			name: "HTTP URL with local flags should pass (local flags ignored)",
			cmd: ActivateCmd{
				Local: true,
				CCM:   true,
				URL:   "https://profiles.example.com/export/p1",
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
			name:    "valid local with CCM",
			cmd:     ActivateCmd{Local: true, CCM: true},
			wantErr: false,
		},
		{
			name:    "valid local with ACM",
			cmd:     ActivateCmd{Local: true, ACM: true},
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
			name:    "implicit local with CCM flag",
			cmd:     ActivateCmd{CCM: true},
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
		// Password flag removed from per-command scope; omit this test.
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

// TestActivateCmd_Validate_PrecendenceMatrix exercises combined flag scenarios to
// ensure precedence logic (local intent vs HTTP(S) URL vs ws/wss vs profile file/name) behaves.
func TestActivateCmd_Validate_PrecendenceMatrix(t *testing.T) {
	tests := []struct {
		name           string
		cmd            ActivateCmd
		wantErr        bool
		wantClearedURL bool
		wantReason     string // substring we expect in error (optional)
	}{
		{
			name:           "Local CCM with HTTP URL causes URL to be cleared (local precedence)",
			cmd:            ActivateCmd{Local: true, CCM: true, URL: "https://server/profile/p1"},
			wantErr:        false,
			wantClearedURL: true,
		},
		{
			name:           "Local ACM with HTTP URL clears URL",
			cmd:            ActivateCmd{Local: true, ACM: true, URL: "http://server/p2"},
			wantErr:        false,
			wantClearedURL: true,
		},
		{
			name:           "HTTP URL remote only (no local flags) retains URL",
			cmd:            ActivateCmd{URL: "https://server/p3"},
			wantErr:        false,
			wantClearedURL: false,
		},
		{
			name:           "ws URL plus local flag fails",
			cmd:            ActivateCmd{Local: true, URL: "wss://rps.example.com/activate", Profile: "prof"},
			wantErr:        true,
			wantClearedURL: false,
			wantReason:     "cannot specify both --local and --url flags",
		},
		{
			name:       "Profile file path with local flags invalid",
			cmd:        ActivateCmd{Profile: "myprofile.yaml", CCM: true},
			wantErr:    true,
			wantReason: "--ccm/--acm/--stopConfig are not valid when --profile points to a file",
		},
		{
			name:    "Profile file path alone succeeds",
			cmd:     ActivateCmd{Profile: "device.enc"},
			wantErr: false,
		},
		{
			name:       "Legacy profile name without ws/wss url fails",
			cmd:        ActivateCmd{Profile: "legacy-name"},
			wantErr:    true,
			wantReason: "--profile as a name requires --url with ws/wss scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy to avoid modifying original test case struct inadvertently
			cmd := tt.cmd

			err := cmd.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error=%v wantErr=%v", err, tt.wantErr)
			}

			if tt.wantErr && tt.wantReason != "" && err != nil && !contains(err.Error(), tt.wantReason) {
				t.Fatalf("error=%q does not contain expected substring %q", err.Error(), tt.wantReason)
			}

			if tt.wantClearedURL && cmd.URL != "" {
				t.Fatalf("expected URL to be cleared, still have %q", cmd.URL)
			}

			if !tt.wantClearedURL && tt.cmd.URL != "" && cmd.URL == "" && !tt.wantErr {
				t.Fatalf("did not expect URL to be cleared (got empty) for scenario: %s", tt.name)
			}
		})
	}
}

// small helper (avoid importing strings in this test addition section since already used above)
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// --- Tests for HTTP profile fullflow helpers ---

func TestAddDeviceToConsole_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/devices", r.URL.Path)

		body, _ := io.ReadAll(r.Body)

		var p device.DevicePayload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Equal(t, "test-guid", p.GUID)
		assert.Equal(t, "test-host", p.Hostname)
		assert.Equal(t, "my-device", p.FriendlyName)
		assert.Equal(t, "amt-pass", p.Password)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "test-host", FriendlyName: "my-device"}
	ctx := &commands.Context{}
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "test-guid", "amt-pass", "mebx-pass", "", false, cfg)
	assert.NoError(t, err)
}

func TestAddDeviceToConsole_FallbackToPatch(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)

			return
		}

		assert.Equal(t, http.MethodPatch, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "host"}
	ctx := &commands.Context{}
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "guid", "pass", "", "", false, cfg)
	assert.NoError(t, err)
	assert.Equal(t, 2, callCount, "should have called POST then PATCH")
}

func TestAddDeviceToConsole_CIRASetsMPSFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		var p device.DevicePayload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Equal(t, "admin", p.MPSUsername)
		assert.Equal(t, "mps-pass", p.MPSPassword)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "host"}
	ctx := &commands.Context{}
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "guid", "pass", "", "mps-pass", true, cfg)
	assert.NoError(t, err)
}

func TestAddDeviceToConsole_NoCIRAClearsMPSFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		var p device.DevicePayload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Empty(t, p.MPSUsername)
		assert.Empty(t, p.MPSPassword)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "host"}
	ctx := &commands.Context{}
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "guid", "pass", "", "mps-pass", false, cfg)
	assert.NoError(t, err)
}

func TestAddDeviceToConsole_FriendlyNameFallsBackToOSHostname(t *testing.T) {
	expectedHostname, _ := os.Hostname()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		var p device.DevicePayload
		require.NoError(t, json.Unmarshal(body, &p))
		assert.Equal(t, expectedHostname, p.FriendlyName)
		assert.Equal(t, "my-host", p.Hostname)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "my-host"} // no FriendlyName set
	ctx := &commands.Context{}
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "guid", "pass", "", "", false, cfg)
	assert.NoError(t, err)
}

func TestResolveTLSFlags_ProfileTLSEnabled(t *testing.T) {
	cmd := &ActivateCmd{}
	cfg := &config.Configuration{}
	cfg.Configuration.TLS.Enabled = true

	useTLS, allowSelfSigned := cmd.resolveTLSFlags(cfg)
	assert.True(t, useTLS)
	assert.True(t, allowSelfSigned)
}

func TestResolveTLSFlags_NoWSMAN(t *testing.T) {
	cmd := &ActivateCmd{} // WSMan is nil
	cfg := &config.Configuration{}

	useTLS, allowSelfSigned := cmd.resolveTLSFlags(cfg)
	assert.False(t, useTLS)
	assert.False(t, allowSelfSigned)
}

func TestResolveTLSFlags_WSMANRemoteTLSEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)

	enumerateResp := amttls.Response{}
	enumerateResp.Body.EnumerateResponse.EnumerationContext = "ctx-123"
	mockWSMAN.EXPECT().EnumerateTLSSettingData().Return(enumerateResp, nil)

	pullResp := amttls.Response{}
	pullResp.Body.PullResponse.SettingDataItems = []amttls.SettingDataResponse{
		{
			InstanceID:                 configure.RemoteTLSInstanceId,
			Enabled:                    true,
			AcceptNonSecureConnections: false,
		},
	}
	mockWSMAN.EXPECT().PullTLSSettingData("ctx-123").Return(pullResp, nil)

	cmd := &ActivateCmd{}
	cmd.WSMan = mockWSMAN
	cfg := &config.Configuration{}

	useTLS, allowSelfSigned := cmd.resolveTLSFlags(cfg)
	assert.True(t, useTLS)
	assert.True(t, allowSelfSigned)
}

func TestResolveTLSFlags_WSMANRemoteTLSAcceptsNonSecure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)

	enumerateResp := amttls.Response{}
	enumerateResp.Body.EnumerateResponse.EnumerationContext = "ctx-456"
	mockWSMAN.EXPECT().EnumerateTLSSettingData().Return(enumerateResp, nil)

	pullResp := amttls.Response{}
	pullResp.Body.PullResponse.SettingDataItems = []amttls.SettingDataResponse{
		{
			InstanceID:                 configure.RemoteTLSInstanceId,
			Enabled:                    true,
			AcceptNonSecureConnections: true, // accepts non-secure → false
		},
	}
	mockWSMAN.EXPECT().PullTLSSettingData("ctx-456").Return(pullResp, nil)

	cmd := &ActivateCmd{}
	cmd.WSMan = mockWSMAN
	cfg := &config.Configuration{}

	useTLS, allowSelfSigned := cmd.resolveTLSFlags(cfg)
	assert.False(t, useTLS)
	assert.False(t, allowSelfSigned)
}

func TestResolveTLSFlags_WSMANEnumerateError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().EnumerateTLSSettingData().Return(amttls.Response{}, errors.New("enumerate failed"))

	cmd := &ActivateCmd{}
	cmd.WSMan = mockWSMAN
	cfg := &config.Configuration{}

	useTLS, allowSelfSigned := cmd.resolveTLSFlags(cfg)
	assert.False(t, useTLS)
	assert.False(t, allowSelfSigned)
}

func TestResolveConsoleInfo_WithUUID(t *testing.T) {
	cmd := &ActivateCmd{UUID: "override-guid"}
	ctx := &commands.Context{}
	fetcher := &profile.ProfileFetcher{URL: "https://console.example.com/api/v1/profiles/p1"}

	baseURL, guid, err := cmd.resolveConsoleInfo(ctx, fetcher)
	assert.NoError(t, err)
	assert.Equal(t, "https://console.example.com", baseURL)
	assert.Equal(t, "override-guid", guid)
}

func TestResolveConsoleInfo_FromAMT(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetUUID().Return("amt-guid-789", nil)

	cmd := &ActivateCmd{}
	ctx := &commands.Context{AMTCommand: mockAMT}
	fetcher := &profile.ProfileFetcher{URL: "https://console.example.com/profile"}

	baseURL, guid, err := cmd.resolveConsoleInfo(ctx, fetcher)
	assert.NoError(t, err)
	assert.Equal(t, "https://console.example.com", baseURL)
	assert.Equal(t, "amt-guid-789", guid)
}

func TestGetLocalIP(t *testing.T) {
	ip := getLocalIP()
	assert.NotEmpty(t, ip)
	assert.NotEqual(t, "unknown", ip, "should resolve to an IP or hostname")
}

func TestResolveConsoleAuth_NoOp(t *testing.T) {
	t.Run("no-op when AuthEndpoint is empty", func(t *testing.T) {
		cmd := &ActivateCmd{}
		ctx := &commands.Context{}

		baseURL, _, _, err := cmd.resolveConsoleAuth(ctx)
		assert.NoError(t, err)
		assert.Empty(t, baseURL)
	})

	t.Run("no-op when AuthEndpoint is relative", func(t *testing.T) {
		cmd := &ActivateCmd{}
		ctx := &commands.Context{}
		ctx.AuthEndpoint = "/api/v1/authorize"

		baseURL, _, _, err := cmd.resolveConsoleAuth(ctx)
		assert.NoError(t, err)
		assert.Empty(t, baseURL)
	})
}

func TestResolveConsoleAuth_WithToken(t *testing.T) {
	cmd := &ActivateCmd{UUID: "test-guid"}
	ctx := &commands.Context{}
	ctx.AuthToken = "my-token"
	ctx.AuthEndpoint = "https://console.example.com/api/v1/authorize"

	baseURL, token, guid, err := cmd.resolveConsoleAuth(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "https://console.example.com", baseURL)
	assert.Equal(t, "my-token", token)
	assert.Equal(t, "test-guid", guid)
}

func TestResolveConsoleAuth_UUIDFromAMT(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetUUID().Return("amt-uuid-123", nil)

	cmd := &ActivateCmd{}
	ctx := &commands.Context{AMTCommand: mockAMT}
	ctx.AuthToken = "token"
	ctx.AuthEndpoint = "https://console.example.com/api/v1/authorize"

	_, _, guid, err := cmd.resolveConsoleAuth(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "amt-uuid-123", guid)
}

func TestAddDeviceToConsole_CustomDevicesEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/custom/v2/devices", r.URL.Path)

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "test-host", FriendlyName: "my-device"}
	ctx := &commands.Context{}
	ctx.DevicesEndpoint = server.URL + "/custom/v2/devices"
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "test-guid", "amt-pass", "mebx-pass", "", false, cfg)
	assert.NoError(t, err)
}

func TestAddDeviceToConsole_CustomDevicesEndpoint_FallbackToPatch(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		assert.Equal(t, "/custom/v2/devices", r.URL.Path)

		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)

			return
		}

		assert.Equal(t, http.MethodPatch, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cmd := &ActivateCmd{Hostname: "host"}
	ctx := &commands.Context{}
	ctx.DevicesEndpoint = server.URL + "/custom/v2/devices"
	cfg := &config.Configuration{}

	err := cmd.addDeviceToConsole(ctx, server.URL, "token", "guid", "pass", "", "", false, cfg)
	assert.NoError(t, err)
	assert.Equal(t, 2, callCount, "should have called POST then PATCH")
}

func TestClearMPSPasswordFromConsole_CustomDevicesEndpoint(t *testing.T) {
	called := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++

		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "/custom/v2/devices", r.URL.Path)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cmd := &ActivateCmd{}
	ctx := &commands.Context{}
	ctx.DevicesEndpoint = server.URL + "/custom/v2/devices"

	cmd.clearMPSPasswordFromConsole(ctx, server.URL, "token", "guid-123")
	assert.Equal(t, 1, called, "expected exactly one PATCH request")
}
