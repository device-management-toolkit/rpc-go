/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package activate provides a public API for AMT activation.
//
// Each mode of the rpc activate command has its own function and options:
// Local activates AMT into CCM or ACM on this device, StopConfiguration
// returns a device that is part way through activation to pre-provisioning,
// Remote lets an RPS server drive activation, and Profile activates and
// configures AMT from a local or Console profile. Every function needs
// elevated privileges (admin/root) to access the HECI driver.
package activate

import (
	"errors"
	"strings"
)

var errRelativeAuthEndpoint = errors.New("AuthEndpoint must be an absolute HTTP(S) URL")

// isHTTPURL reports whether raw has the http or https scheme, ignoring case,
// the way the activate command tells URLs apart.
func isHTTPURL(raw string) bool {
	lower := strings.ToLower(raw)

	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// isWebSocketURL reports whether raw has the ws or wss scheme, ignoring case,
// the way the activate command tells URLs apart.
func isWebSocketURL(raw string) bool {
	lower := strings.ToLower(raw)

	return strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://")
}
