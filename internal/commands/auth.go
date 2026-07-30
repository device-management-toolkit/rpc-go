/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// ServerAuthFlags provides common auth options for server communications.
// When AuthEndpoint is set, either AuthToken (Bearer) OR both AuthUsername
// and AuthPassword (Basic) must be supplied.
type ServerAuthFlags struct {
	AuthToken       string `help:"Bearer token for server authentication" name:"auth-token" env:"AUTH_TOKEN"`
	AuthUsername    string `help:"Username for basic auth (used when no token)" name:"auth-username" env:"AUTH_USERNAME"`
	AuthPassword    string `help:"Password for basic auth (used when no token)" name:"auth-password" env:"AUTH_PASSWORD"`
	AuthEndpoint    string `help:"Token exchange endpoint. Requires --auth-token or --auth-username/--auth-password. Resolved relative to the profile URL host unless absolute." name:"auth-endpoint" env:"AUTH_ENDPOINT"`
	DevicesEndpoint string `help:"Devices API endpoint (absolute URL). Defaults to {console-url}/api/v1/devices when not set." name:"devices-endpoint" env:"DEVICES_ENDPOINT"`
}

// Validate implements kong.Validatable.
// - auth-username and auth-password must always be provided together.
// - When auth-endpoint is set, either auth-token or (auth-username + auth-password) is required.
// - When devices-endpoint is set, it must be an absolute HTTP(S) URL.
func (a *ServerAuthFlags) Validate() error {
	if a.DevicesEndpoint != "" {
		parsed, err := url.Parse(a.DevicesEndpoint)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("--devices-endpoint must be an absolute HTTP(S) URL")
		}
	}

	if (a.AuthUsername != "") != (a.AuthPassword != "") {
		if a.AuthUsername != "" {
			return fmt.Errorf("--auth-username requires --auth-password")
		}

		return fmt.Errorf("--auth-password requires --auth-username")
	}

	if a.AuthEndpoint == "" {
		return nil
	}

	if a.AuthToken != "" {
		return nil
	}

	if a.AuthUsername != "" && a.AuthPassword != "" {
		return nil
	}

	return fmt.Errorf("--auth-endpoint requires --auth-token or both --auth-username and --auth-password")
}

// ValidateRequired enforces that some form of auth is present when required.
// If required is false, this performs no validation.
func (a *ServerAuthFlags) ValidateRequired(required bool) error {
	logrus.Debugf("validating server auth flags")

	if !required {
		return nil
	}

	if a == nil {
		return fmt.Errorf("authentication is required: provide --auth-token or --auth-username and --auth-password")
	}

	if a.AuthToken != "" {
		return nil
	}

	if a.AuthUsername != "" && a.AuthPassword != "" {
		return nil
	}

	return fmt.Errorf("authentication is required: provide --auth-token or --auth-username and --auth-password")
}

// AfterApply runs after Kong binds flags and prints security warnings if needed.
// This hook is called automatically by Kong's lifecycle after flag parsing completes.
func (a *ServerAuthFlags) AfterApply() error {
	a.WarnIfInsecure()

	return nil
}

// WarnIfInsecure prints a deprecation warning if credentials were passed via CLI flags
// instead of environment variables. Credentials passed on the command line are visible
// in process listings (ps, htop, /proc/<pid>/cmdline), which is a security risk.
func (a *ServerAuthFlags) WarnIfInsecure() {
	// Check if credentials are present (from any source)
	hasToken := strings.TrimSpace(a.AuthToken) != ""
	hasUsername := strings.TrimSpace(a.AuthUsername) != ""
	hasPassword := strings.TrimSpace(a.AuthPassword) != ""

	if !hasToken && !hasUsername && !hasPassword {
		return // No credentials, no warning needed
	}

	// Helper to detect if a flag was explicitly passed on the command line
	flagPresent := func(name string) bool {
		prefix := name + "="
		for _, arg := range os.Args[1:] {
			if arg == name || strings.HasPrefix(arg, prefix) {
				return true
			}
		}

		return false
	}

	// Detect whether credentials were explicitly passed via CLI flags
	var cliFlags []string

	if hasToken && flagPresent("--auth-token") {
		cliFlags = append(cliFlags, "--auth-token")
	}

	if hasUsername && flagPresent("--auth-username") {
		cliFlags = append(cliFlags, "--auth-username")
	}

	if hasPassword && flagPresent("--auth-password") {
		cliFlags = append(cliFlags, "--auth-password")
	}

	if len(cliFlags) > 0 {
		const separator = "-------------------------------------------------------------------"

		logrus.Warnf(separator)
		logrus.Warnf("SECURITY WARNING: Credentials passed via CLI flags (%s)", strings.Join(cliFlags, ", "))
		logrus.Warn("These are visible in process listings and may be captured in system logs.")
		logrus.Warn("Use environment variables instead:")

		if flagPresent("--auth-token") {
			logrus.Warn("  AUTH_TOKEN=<your-token>")
		}

		if flagPresent("--auth-username") || flagPresent("--auth-password") {
			logrus.Warn("  AUTH_USERNAME=<username>")
			logrus.Warn("  AUTH_PASSWORD=<password>")
		}

		logrus.Warnf(separator)
	}
}

// ApplyToRequest sets the appropriate Authorization header on the request if any auth is provided.
// Preference order: Bearer token, then Basic auth when both username and password are present.
func (a *ServerAuthFlags) ApplyToRequest(req *http.Request) {
	if a == nil {
		return
	}

	if a.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.AuthToken)

		return
	}

	if a.AuthUsername != "" && a.AuthPassword != "" {
		// Basic base64(username:password)
		creds := a.AuthUsername + ":" + a.AuthPassword
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
}
