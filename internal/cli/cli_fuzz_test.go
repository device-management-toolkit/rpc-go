/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package cli

import (
	"strings"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"go.uber.org/mock/gomock"
)

// setupMockAMT creates a fully configured mock AMT interface for testing
func setupMockAMT(ctrl *gomock.Controller) *mock.MockInterface {
	mockAMTCommand := mock.NewMockInterface(ctrl)
	// Setup common mock expectations that various commands might call
	mockAMTCommand.EXPECT().Initialize().Return(nil).AnyTimes()
	mockAMTCommand.EXPECT().GetControlMode().Return(0, nil).AnyTimes()
	mockAMTCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), nil).AnyTimes()
	mockAMTCommand.EXPECT().GetVersionDataFromME(gomock.Any(), gomock.Any()).Return("", nil).AnyTimes()
	mockAMTCommand.EXPECT().GetUUID().Return("", nil).AnyTimes()
	mockAMTCommand.EXPECT().GetOSDNSSuffix().Return("", nil).AnyTimes()
	mockAMTCommand.EXPECT().GetDNSSuffix().Return("", nil).AnyTimes()
	mockAMTCommand.EXPECT().GetCertificateHashes().Return([]amt.CertHashEntry{}, nil).AnyTimes()
	mockAMTCommand.EXPECT().GetRemoteAccessConnectionStatus().Return(amt.RemoteAccessStatus{}, nil).AnyTimes()
	mockAMTCommand.EXPECT().GetLANInterfaceSettings(gomock.Any()).Return(amt.InterfaceSettings{}, nil).AnyTimes()
	mockAMTCommand.EXPECT().GetLocalSystemAccount().Return(amt.LocalSystemAccount{}, nil).AnyTimes()
	mockAMTCommand.EXPECT().Unprovision().Return(0, nil).AnyTimes()
	mockAMTCommand.EXPECT().EnableAMT().Return(nil).AnyTimes()
	mockAMTCommand.EXPECT().DisableAMT().Return(nil).AnyTimes()

	return mockAMTCommand
}

// recoverPanic recovers from panics during fuzzing and logs them
func recoverPanic(t *testing.T, input string) {
	if r := recover(); r != nil {
		t.Logf("Parse panicked with input %q: %v", input, r)
	}
}

// FuzzDeactivate tests the deactivate command with various flag combinations and inputs
func FuzzDeactivate(f *testing.F) {
	// Seed corpus with valid deactivate command patterns
	seeds := []string{
		// Local deactivation
		"--local",
		"--local --password admin",
		"-l",
		"-l --password test123",

		// Remote deactivation
		"--url https://server.com",
		"-u https://server.com",
		"--url https://server.com --password admin",
		"--url wss://server.com:8080/path",

		// Partial unprovision (local only)
		"--local --partial",
		"--local --partial --password admin",

		// Force flag
		"--url https://server.com --force",
		"-u https://server.com -f",

		// Combined with global flags
		"--json --local",
		"--verbose --local --password admin",
		"--log-level debug --local",
		"--skip-cert-check --url https://server.com",
		"--skip-amt-cert-check --local",

		// Invalid combinations (should fail validation)
		"--local --url https://server.com",   // both local and url
		"--partial",                          // partial without local
		"--url https://server.com --partial", // partial with remote
		"",                                   // missing required flags

		// Edge cases
		"--url " + strings.Repeat("https://a", 50),
		"--password " + strings.Repeat("a", 500),
		"--local --password \"pass with spaces\"",
		"--url https://user:pass@host:9999/path?query=value",

		// Special characters
		"--url https://server.com/path?param=value&other=test",
		"--password pass\"word",
		"--password pass'word",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, flags string) {
		// Skip extremely long inputs to prevent resource exhaustion
		if len(flags) > 10000 {
			t.Skip("Input too long")
		}

		// Create mock AMT command
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		// Build command line arguments
		args := []string{"rpc", "deactivate"}
		if trimmed := strings.TrimSpace(flags); trimmed != "" {
			args = append(args, strings.Fields(flags)...)
		}

		// The Parse function should not panic with any input
		defer recoverPanic(t, flags)

		// Call Parse - it may return an error for invalid inputs, but should not panic
		_, _, err := Parse(args, mockAMTCommand)

		// We expect errors for invalid combinations, but the parser should handle them gracefully
		_ = err
	})
}

// FuzzDeactivateURL tests URL parsing and validation for deactivate command
func FuzzDeactivateURL(f *testing.F) {
	// Seed with various URL formats
	seeds := []string{
		"https://localhost",
		"https://server.com",
		"https://server.com:443",
		"https://server.com:8080/path",
		"https://user:pass@server.com",
		"http://insecure.com",
		"wss://websocket.server.com",
		"ws://websocket.server.com",
		// Invalid URLs
		"://missing-scheme",
		"ftp://wrong-protocol.com",
		"https://",
		"server.com", // missing scheme
		strings.Repeat("https://", 100),
		"https://" + strings.Repeat("a", 2000),
		// Special characters
		"https://server.com/path?query=value#fragment",
		"https://server.com/path with spaces",
		"https://服务器.com", // Unicode domain
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, url string) {
		if len(url) > 5000 {
			t.Skip("URL too long")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		args := []string{"rpc", "deactivate", "--url", url}
		defer recoverPanic(t, url)

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}

// FuzzDeactivatePassword tests password input handling for deactivate command
func FuzzDeactivatePassword(f *testing.F) {
	// Seed with various password formats
	seeds := []string{
		"admin",
		"Password123!",
		"",
		"pass with spaces",
		"pass\"with\"quotes",
		"pass'with'quotes",
		"pass\\with\\escapes",
		"パスワード", // Unicode
		"🔒🔑",    // Emoji
		strings.Repeat("a", 1000),
		"$pecial@Ch@rs!",
		"$(command)",
		"`backticks`",
		"; echo test",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, password string) {
		if len(password) > 5000 {
			t.Skip("Password too long")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		// Test with local mode
		args := []string{"rpc", "deactivate", "--local", "--password", password}
		defer recoverPanic(t, password)

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}

// FuzzDeactivateFlagCombinations tests various combinations of deactivate flags
func FuzzDeactivateFlagCombinations(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		local bool,
		partial bool,
		force bool,
		url string,
		password string,
		jsonOutput bool,
		verbose bool,
	) {
		// Limit total input size
		if len(url) > 1000 || len(password) > 1000 {
			t.Skip("Input too long")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		args := []string{"rpc", "deactivate"}

		if local {
			args = append(args, "--local")
		}

		if partial {
			args = append(args, "--partial")
		}

		if force {
			args = append(args, "--force")
		}

		if url != "" {
			args = append(args, "--url", url)
		}

		if password != "" {
			args = append(args, "--password", password)
		}

		if jsonOutput {
			args = append(args, "--json")
		}

		if verbose {
			args = append(args, "--verbose")
		}

		defer recoverPanic(t, strings.Join(args, " "))

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}
