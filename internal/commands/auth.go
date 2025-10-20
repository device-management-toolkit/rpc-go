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

// ServerAuthFlags provides common auth options for server communications
// Either AuthToken (Bearer) OR both AuthUsername and AuthPassword (Basic) should be supplied.
type ServerAuthFlags struct {
	AuthToken    string `help:"Bearer token for server authentication" name:"auth-token" env:"AUTH_TOKEN"`
	AuthUsername string `help:"Username for basic auth (used when no token)" name:"auth-username" env:"AUTH_USERNAME"`
	AuthPassword string `help:"Password for basic auth (used when no token)" name:"auth-password" env:"AUTH_PASSWORD"`
	// Optional endpoint for exchanging credentials for a token (primarily used when fetching HTTP profiles)
	AuthEndpoint string `help:"The endpoint to call to fetch a token. Assumes the same host as the profile URL unless an absolute URL is provided; defaults to the Console path /api/v1/authorize." name:"auth-endpoint" default:"/api/v1/authorize"`
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
