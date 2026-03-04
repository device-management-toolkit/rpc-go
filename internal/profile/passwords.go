/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

import (
	"fmt"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/sirupsen/logrus"
)

const randomPasswordLength = 16

// ResolvePasswords generates or retrieves AMT admin, MEBx, and MPS passwords
// from the profile configuration. When a "generate random" flag is set, a random
// password is created and written back into cfg so the orchestrator uses it.
func ResolvePasswords(cfg *config.Configuration) (amtPassword, mebxPassword, mpsPassword string, err error) {
	// AMT admin password
	if cfg.Configuration.AMTSpecific.GenerateRandomPassword {
		amtPassword, err = utils.GenerateRandomPassword(randomPasswordLength)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate random AMT password: %w", err)
		}

		cfg.Configuration.AMTSpecific.AdminPassword = amtPassword

		logrus.Debug("Generated random AMT admin password")
	} else {
		amtPassword = cfg.Configuration.AMTSpecific.AdminPassword
	}

	// MEBx password
	if cfg.Configuration.AMTSpecific.GenerateRandomMEBXPassword {
		mebxPassword, err = utils.GenerateRandomPassword(randomPasswordLength)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate random MEBx password: %w", err)
		}

		cfg.Configuration.AMTSpecific.MEBXPassword = mebxPassword

		logrus.Debug("Generated random MEBx password")
	} else {
		mebxPassword = cfg.Configuration.AMTSpecific.MEBXPassword
	}

	// MPS password
	if cfg.Configuration.AMTSpecific.CIRA.GenerateRandomPassword {
		mpsPassword, err = utils.GenerateRandomPassword(randomPasswordLength)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to generate random MPS password: %w", err)
		}

		cfg.Configuration.AMTSpecific.CIRA.MPSPassword = mpsPassword

		logrus.Debug("Generated random MPS password")
	} else {
		mpsPassword = cfg.Configuration.AMTSpecific.CIRA.MPSPassword
	}

	return amtPassword, mebxPassword, mpsPassword, nil
}
