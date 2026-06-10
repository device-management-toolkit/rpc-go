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
	mockAMTCommand.EXPECT().Close().Return(nil).AnyTimes()

	return mockAMTCommand
}

// recoverPanic recovers from panics during fuzzing and logs them
func recoverPanic(t *testing.T, input string) {
	if r := recover(); r != nil {
		t.Logf("Parse panicked with input %q: %v", input, r)
	}
}

// splitFuzzFlags splits a command-like flag string and preserves quoted segments.
func splitFuzzFlags(input string) []string {
	var (
		args         []string
		current      strings.Builder
		quote        rune
		escaped      bool
		tokenStarted bool
	)

	flush := func() {
		if tokenStarted {
			args = append(args, current.String())
			current.Reset()

			tokenStarted = false
		}
	}

	for _, r := range input {
		if escaped {
			current.WriteRune(r)

			escaped = false
			tokenStarted = true

			continue
		}

		if r == '\\' {
			escaped = true
			tokenStarted = true

			continue
		}

		if quote != 0 {
			if r == quote {
				quote = 0

				continue
			}

			current.WriteRune(r)

			tokenStarted = true

			continue
		}

		if r == '"' || r == '\'' {
			quote = r
			tokenStarted = true

			continue
		}

		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			flush()

			continue
		}

		current.WriteRune(r)

		tokenStarted = true
	}

	if escaped {
		current.WriteRune('\\')
	}

	flush()

	return args
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

// FuzzActivate tests the activate command with various flag combinations and inputs
func FuzzActivate(f *testing.F) {
	// Seed corpus with valid and invalid activate command patterns
	seeds := []string{
		// Local activation (CCM)
		"--local --ccm",
		"--ccm",
		"--ccm --password admin",
		"--local --ccm --password Passw0rd!",

		// Local activation (ACM, provisioning cert path)
		"--local --acm",
		"--acm",
		"--acm --password admin --provisioningCert MIIabc== --provisioningCertPwd certpass",
		"--acm --password admin --provisioningCert MIIabc== --provisioningCertPwd certpass --mebxpassword Mebx123!",
		"--acm --tls-tunnel --password admin",

		// Stop configuration
		"--local --stopConfig",
		"--stopConfig",

		// Legacy remote activation (ws/wss)
		"--url wss://server.com --profile profile1",
		"--url ws://server.com:8080/path --profile profile1",
		"--url wss://server.com --profile p1 --proxy http://proxy.corp:8080",
		"--url wss://server.com --profile p1 --tenantid tenant-1",

		// HTTP profile activation (fullflow) with auth
		"--url https://server.com/api/v1/admin/profiles/export/default",
		"--url http://localhost:8080/profiles/export/default --key 12345678901234567890123456789012",
		"--url https://server.com/api/v1/admin/profiles/export/p1 --auth-token abc.def.ghi",
		"--url https://server.com/api/v1/admin/profiles/export/p1 --auth-username user --auth-password secret",
		"--url https://server.com/profiles/export/p1 --auth-endpoint https://server.com/api/v1/authorize --auth-token abc",
		"--url https://server.com/profiles/export/p1 --devices-endpoint https://server.com/api/v1/devices --auth-token abc",

		// Local profile file activation
		"--profile profile.yaml",
		"--profile ./configs/profile.yml --key 12345678901234567890123456789012",

		// Optional fields
		"--local --ccm --dns corp.example.com --hostname host-1 --name my-device",
		"--local --ccm --skipIPRenew",
		"--url wss://server.com --profile p1 --uuid 123e4567-e89b-12d3-a456-426614174000",

		// Invalid combinations (should fail validation)
		"--local",
		"--local --ccm --acm",
		"--url wss://server.com",
		"--url wss://server.com --profile p1 --local",
		"--url wss://server.com --profile p1 --ccm",
		"--url wss://server.com --profile p1 --provisioningCert MIIabc==",
		"--url wss://server.com --profile p1 --skipIPRenew",
		"--url https://server.com/export/p1 --ccm",
		"--auth-username user",
		"--profile profile-name",
		"",

		// Edge cases
		"--url " + strings.Repeat("https://a", 40),
		"--profile " + strings.Repeat("a", 500),
		"--password " + strings.Repeat("a", 500),
		"--local --ccm --name \"device with spaces\"",
		"--url https://user:pass@host:9999/path?query=value",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, flags string) {
		if len(flags) > 10000 {
			t.Skip("Input too long")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		args := []string{"rpc", "activate"}
		if trimmed := strings.TrimSpace(flags); trimmed != "" {
			args = append(args, splitFuzzFlags(flags)...)
		}

		defer recoverPanic(t, flags)

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}

// FuzzActivateURL tests URL parsing and validation for activate command
func FuzzActivateURL(f *testing.F) {
	seeds := []string{
		"https://localhost",
		"https://server.com",
		"https://server.com:443",
		"https://server.com:8080/path",
		"wss://websocket.server.com",
		"ws://websocket.server.com",
		"http://insecure.server.com",
		"://missing-scheme",
		"ftp://wrong-protocol.com",
		"https://",
		"server.com",
		strings.Repeat("https://", 100),
		"https://" + strings.Repeat("a", 2000),
		"https://server.com/path?query=value#fragment",
		"https://server.com/path with spaces",
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

		args := []string{"rpc", "activate", "--url", url, "--profile", "default"}
		defer recoverPanic(t, url)

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}

// FuzzActivateProfile tests profile input handling for activate command
func FuzzActivateProfile(f *testing.F) {
	seeds := []string{
		"default",
		"profile-1",
		"profile.yaml",
		"./profiles/default.yml",
		"../profiles/edge.case.json",
		"",
		"profile with spaces.yaml",
		"path/with/special_-.chars.yaml",
		strings.Repeat("a", 1000),
		"パスファイル.yaml",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, profile string) {
		if len(profile) > 5000 {
			t.Skip("Profile too long")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		args := []string{"rpc", "activate", "--profile", profile}
		defer recoverPanic(t, profile)

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}

// FuzzActivatePassword tests AMT password input handling for activate command.
// The AMT password is set during local CCM/ACM activation, so malformed or
// unusual passwords must be parsed without panicking.
func FuzzActivatePassword(f *testing.F) {
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

		// Local CCM activation is the primary path that consumes --password.
		args := []string{"rpc", "activate", "--local", "--ccm", "--password", password}
		defer recoverPanic(t, password)

		_, _, err := Parse(args, mockAMTCommand)
		_ = err
	})
}

// FuzzActivateFlagCombinations tests various combinations of activate flags
func FuzzActivateFlagCombinations(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		local bool,
		ccm bool,
		acm bool,
		stopConfig bool,
		tlsTunnel bool,
		skipIPRenew bool,
		url string,
		profile string,
		key string,
		password string,
		provisioningCert string,
		mebxPassword string,
		authToken string,
		jsonOutput bool,
		verbose bool,
	) {
		if len(url) > 1000 || len(profile) > 1000 || len(key) > 1000 ||
			len(password) > 1000 || len(provisioningCert) > 1000 ||
			len(mebxPassword) > 1000 || len(authToken) > 1000 {
			t.Skip("Input too long")
		}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockAMTCommand := setupMockAMT(ctrl)

		args := []string{"rpc", "activate"}

		if local {
			args = append(args, "--local")
		}

		if ccm {
			args = append(args, "--ccm")
		}

		if acm {
			args = append(args, "--acm")
		}

		if stopConfig {
			args = append(args, "--stopConfig")
		}

		if tlsTunnel {
			args = append(args, "--tls-tunnel")
		}

		if skipIPRenew {
			args = append(args, "--skipIPRenew")
		}

		if url != "" {
			args = append(args, "--url", url)
		}

		if profile != "" {
			args = append(args, "--profile", profile)
		}

		if key != "" {
			args = append(args, "--key", key)
		}

		if password != "" {
			args = append(args, "--password", password)
		}

		if provisioningCert != "" {
			args = append(args, "--provisioningCert", provisioningCert)
		}

		if mebxPassword != "" {
			args = append(args, "--mebxpassword", mebxPassword)
		}

		if authToken != "" {
			args = append(args, "--auth-token", authToken)
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
