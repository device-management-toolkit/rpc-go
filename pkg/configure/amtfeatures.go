/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// AMTFeaturesOptions configures AMT features (KVM, SOL, IDER, user consent).
type AMTFeaturesOptions struct {
	BaseOptions
	// UserConsent sets the user consent policy. Valid values: "kvm", "all", "none".
	// Only applies in ACM mode. Defaults to "all" if empty.
	UserConsent string
	// KVM enables Keyboard/Video/Mouse redirection.
	KVM bool
	// SOL enables Serial Over LAN.
	SOL bool
	// IDER enables IDE Redirection.
	IDER bool
}

// SetAMTFeatures configures AMT features including KVM, SOL, IDER, and user consent.
// Requires the device to be activated.
func SetAMTFeatures(opts AMTFeaturesOptions) error {
	cmd := &internalcfg.AMTFeaturesCmd{}
	cmd.KVM = opts.KVM
	cmd.SOL = opts.SOL
	cmd.IDER = opts.IDER
	cmd.UserConsent = opts.UserConsent

	if cmd.UserConsent == "" {
		cmd.UserConsent = "all"
	}

	return run(cmd, opts.BaseOptions)
}
