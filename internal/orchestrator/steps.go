/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import "github.com/device-management-toolkit/rpc-go/v2/pkg/configure"

// The profile steps run in-process through these pkg/configure calls; tests
// replace them to check the options each step builds.
var (
	configureChangeAMTPassword = configure.ChangeAMTPassword
	configureSetMEBx           = configure.SetMEBx
	configureSetAMTFeatures    = configure.SetAMTFeatures
	configureWired             = configure.ConfigureWired
	configureWiFiSync          = configure.ConfigureWiFiSync
	configureWireless          = configure.ConfigureWireless
	configureTLS               = configure.ConfigureTLS
	configureCIRA              = configure.ConfigureCIRA
)
