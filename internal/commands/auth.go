/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

// ServerAuthFlags provides common auth options for server communications.
// When AuthEndpoint is set, either AuthToken (Bearer) OR both AuthUsername
// and AuthPassword (Basic) must be supplied.
type ServerAuthFlags struct {
	AuthToken    string `help:"Bearer token for server authentication" name:"auth-token" env:"AUTH_TOKEN"`
	AuthUsername string `help:"Username for basic auth (used when no token)" name:"auth-username" env:"AUTH_USERNAME"`
	AuthPassword string `help:"Password for basic auth (used when no token)" name:"auth-password" env:"AUTH_PASSWORD"`
	AuthEndpoint string `help:"Token exchange endpoint. Requires --auth-token or --auth-username/--auth-password. Resolved relative to the profile URL host unless absolute." name:"auth-endpoint" env:"AUTH_ENDPOINT"`
}

// Validate implements kong.Validatable.
// - auth-username and auth-password must always be provided together.
// - When auth-endpoint is set, either auth-token or (auth-username + auth-password) is required.
func (a *ServerAuthFlags) Validate() error {
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
