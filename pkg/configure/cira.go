/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	internalcfg "github.com/device-management-toolkit/rpc-go/v2/internal/commands/configure"
)

// CIRAOptions configures Cloud-Initiated Remote Access on the AMT device.
type CIRAOptions struct {
	BaseOptions
	// MPSPassword is the MPS password.
	MPSPassword string
	// MPSAddress is the MPS server address (required).
	MPSAddress string
	// MPSCert is the MPS root public certificate (required).
	MPSCert string
	// EnvironmentDetection is a list of environment detection strings.
	EnvironmentDetection []string
	// GenerateRandomPassword generates a random password for MPS connection.
	GenerateRandomPassword bool
}

// ConfigureCIRA configures Cloud-Initiated Remote Access (CIRA) on the AMT device.
func ConfigureCIRA(opts CIRAOptions) error {
	cmd := &internalcfg.CIRACmd{}
	cmd.MPSPassword = opts.MPSPassword
	cmd.MPSAddress = opts.MPSAddress
	cmd.MPSCert = opts.MPSCert
	cmd.EnvironmentDetection = opts.EnvironmentDetection
	cmd.GenerateRandomPassword = opts.GenerateRandomPassword

	return run(cmd, opts.BaseOptions)
}
