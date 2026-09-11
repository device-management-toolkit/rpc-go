/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package commands

import (
	"crypto/tls"
	"strings"
	"sync"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	log "github.com/sirupsen/logrus"
)

// Context holds shared dependencies injected into commands
type Context struct {
	AMTCommand    amt.Interface
	ControlMode   int
	LogLevel      string
	JsonOutput    bool
	TableOutput   bool
	NoColor       bool
	Verbose       bool
	SkipCertCheck bool
	// SkipAMTCertCheck controls whether to skip TLS verification when connecting to AMT/LMS over TLS
	// This is distinct from SkipCertCheck which applies to remote RPS HTTPS/WSS connections.
	SkipAMTCertCheck bool
	TLSConfig        *tls.Config
	TenantID         string
	AMTPassword      string // Centralized AMT admin password (from global flag/env or interactive prompt)
	ServerAuthFlags
}

// securityWarningSeparator frames the security warning banner printed by logSecurityWarning.
const securityWarningSeparator = "-------------------------------------------------------------------"

// logSecurityWarning prints the standard banner warning that credentials were passed
// via CLI flags. envLines, when non-empty, are rendered as "NAME=<value>" suggestions;
// when empty, a generic recommendation is printed instead.
func logSecurityWarning(flagsDesc string, envLines []string) {
	log.Warn(securityWarningSeparator)
	log.Warnf("SECURITY WARNING: Credentials passed via CLI flags (%s)", flagsDesc)
	log.Warn("These are visible in process listings and may be captured in system logs.")

	if len(envLines) > 0 {
		log.Warn("Use environment variables instead:")

		for _, line := range envLines {
			log.Warnf("  %s", line)
		}
	} else {
		log.Warn("Consider providing this value via a config file or interactive prompt instead.")
	}

	log.Warn(securityWarningSeparator)
}

// CredentialCLI describes a sensitive value and its CLI flag aliases.
type CredentialCLI struct {
	Value    string
	EnvVar   string
	FlagName []string
}

var (
	parsedCLIArgsMu sync.RWMutex
	parsedCLIArgs   []string
)

// SetParsedCLIArgs records the args that Kong parsed, excluding the program name.
func SetParsedCLIArgs(args []string) func() {
	parsedCLIArgsMu.Lock()
	defer parsedCLIArgsMu.Unlock()

	previous := parsedCLIArgs

	parsedCLIArgs = append([]string(nil), args...)

	return func() {
		parsedCLIArgsMu.Lock()
		defer parsedCLIArgsMu.Unlock()

		parsedCLIArgs = previous
	}
}

var (
	credentialWarningMu    sync.Mutex
	credentialWarningBatch bool
	batchedCredentials     []CredentialCLI
)

// BeginCredentialWarningBatch causes subsequent WarnIfCredentialsOnCLI calls to buffer
// their credentials instead of warning immediately, so that all credentials detected
// while parsing a single command (across Globals, ServerAuthFlags, and any subcommand
// flags) are reported in one consolidated banner. Call EndCredentialWarningBatch to
// flush the buffer and resume immediate warnings.
func BeginCredentialWarningBatch() {
	credentialWarningMu.Lock()
	defer credentialWarningMu.Unlock()

	credentialWarningBatch = true
	batchedCredentials = nil
}

// EndCredentialWarningBatch flushes any credentials buffered since BeginCredentialWarningBatch
// as a single warning banner, then stops batching.
func EndCredentialWarningBatch() {
	credentialWarningMu.Lock()
	credentialWarningBatch = false
	pending := batchedCredentials
	batchedCredentials = nil
	credentialWarningMu.Unlock()

	if len(pending) > 0 {
		emitCredentialWarning(pending...)
	}
}

// WarnIfCredentialsOnCLI prints one warning for all non-empty credentials passed
// via command-line flags. EnvVar is suggested when it is provided. When called
// between BeginCredentialWarningBatch/EndCredentialWarningBatch, the credentials
// are buffered and reported together instead of warning immediately.
func WarnIfCredentialsOnCLI(credentials ...CredentialCLI) {
	credentialWarningMu.Lock()
	if credentialWarningBatch {
		batchedCredentials = append(batchedCredentials, credentials...)
		credentialWarningMu.Unlock()

		return
	}
	credentialWarningMu.Unlock()

	emitCredentialWarning(credentials...)
}

// emitCredentialWarning does the actual flag matching and warning for a batch of credentials.
func emitCredentialWarning(credentials ...CredentialCLI) {
	var cliFlags []string

	var envLines []string

	for _, credential := range credentials {
		if strings.TrimSpace(credential.Value) == "" {
			continue
		}

		matched := ""

		for _, name := range credential.FlagName {
			flag := name
			if !strings.HasPrefix(flag, "-") {
				if len(name) == 1 {
					flag = "-" + name
				} else {
					flag = "--" + name
				}
			}

			if flagPresentOnCLI(flag) {
				matched = flag

				break
			}
		}

		if matched == "" {
			continue
		}

		cliFlags = append(cliFlags, matched)
		if credential.EnvVar != "" {
			envLines = append(envLines, credential.EnvVar+"=<value>")
		}
	}

	if len(cliFlags) > 0 {
		logSecurityWarning(strings.Join(cliFlags, ", "), envLines)
	}
}

// flagPresentOnCLI reports whether flag was explicitly passed as a command-line argument
// (as opposed to being populated from an environment variable or config file default).
func flagPresentOnCLI(flag string) bool {
	parsedCLIArgsMu.RLock()

	args := append([]string(nil), parsedCLIArgs...)

	parsedCLIArgsMu.RUnlock()

	for _, arg := range args {
		if arg == flag || strings.HasPrefix(arg, flag+"=") {
			return true
		}

		// Support short flags with an attached value, e.g. -kVALUE
		if len(flag) == 2 && strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") && strings.HasPrefix(arg, flag) {
			return true
		}
	}

	return false
}
