/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// AMTPasswordCmd represents AMT password change
type AMTPasswordCmd struct {
	ConfigureBaseCmd

	NewPassword string `help:"New AMT password" name:"newamtpassword"`
}

// BeforeApply validates the AMT password change command before execution
func (cmd *AMTPasswordCmd) Validate() error {
	// First call the base Validate to handle password validation
	if err := cmd.ConfigureBaseCmd.Validate(); err != nil {
		return err
	}

	// Validate new AMT password - prompt if not provided
	if cmd.NewPassword == "" {
		fmt.Print("New AMT Password: ")

		password, err := utils.PR.ReadPassword()
		if err != nil {
			return fmt.Errorf("failed to read new AMT password: %w", err)
		}

		cmd.NewPassword = password
	}

	return nil
}

// Run executes the AMT password change command
func (cmd *AMTPasswordCmd) Run(ctx *commands.Context) error {
	// Ensure runtime initialization (password + WSMAN client)
	if err := cmd.EnsureRuntime(ctx); err != nil {
		return err
	}

	log.Info("Changing AMT password...")

	// Validate that device is activated before changing password
	controlMode := cmd.GetControlMode()

	// Device must be activated (not in pre-provisioning state)
	if controlMode == 0 {
		log.Error(ErrDeviceNotActivated)

		return ErrDeviceNotActivated
	}

	// Get general settings to obtain digest realm
	generalSettings, err := cmd.WSMan.GetGeneralSettings()
	if err != nil {
		// AMT 20/21 may need a moment after WSMAN client setup before accepting requests
		// Retry once if we get EOF or connection error
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection") {
			log.Debug("First GetGeneralSettings failed, retrying...")
			time.Sleep(1 * time.Second)

			generalSettings, err = cmd.WSMan.GetGeneralSettings()
			if err != nil {
				return fmt.Errorf("failed to get AMT general settings: %s", sanitizeAMTPassError(err))
			}
		} else {
			return fmt.Errorf("failed to get AMT general settings: %s", sanitizeAMTPassError(err))
		}
	}

	// Create authentication challenge with new password
	challenge := client.AuthChallenge{
		Username: utils.AMTUserName,
		Password: cmd.NewPassword,
		Realm:    generalSettings.Body.GetResponse.DigestRealm,
	}

	// Hash the credentials
	hashedMessage := challenge.HashCredentials()

	// Decode hex string to bytes
	bytes, err := hex.DecodeString(hashedMessage)
	if err != nil {
		return fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Encode to base64
	encodedMessage := base64.StdEncoding.EncodeToString(bytes)

	// Update the AMT password
	response, err := cmd.WSMan.UpdateAMTPassword(encodedMessage)
	if err != nil {
		return fmt.Errorf("failed to update AMT password: %s", sanitizeAMTPassError(err))
	}

	log.Trace(response)
	log.Info("Successfully updated AMT Password.")

	return nil
}

// sanitizeAMTPassError converts noisy AMT/WSMAN errors (including raw HTML bodies)
// into concise, user-friendly messages without leaking raw markup.
func sanitizeAMTPassError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()
	lower := strings.ToLower(msg)

	// Per request: stop being fancy. If we see a 401 anywhere, surface a concise message.
	if strings.Contains(lower, "401") {
		return "Received 401 unauthorized"
	}

	// Otherwise, just return the original error message.
	return msg
}
