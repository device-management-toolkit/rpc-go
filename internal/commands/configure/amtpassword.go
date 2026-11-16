/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package configure

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// AMTPasswordCmd represents AMT password change
type AMTPasswordCmd struct {
	ConfigureBaseCmd

	NewPassword string `help:"New AMT password" name:"newamtpassword" env:"NEW_AMT_PASSWORD"`
}

// AfterApply prints a security warning if the new AMT password was passed via CLI flag.
func (cmd *AMTPasswordCmd) AfterApply(amtCommand amt.Interface) error {
	if err := cmd.AMTBaseCmd.AfterApply(amtCommand); err != nil {
		return err
	}

	commands.WarnIfCredentialsOnCLI(commands.CredentialCLI{Value: cmd.NewPassword, FlagName: []string{"newamtpassword"}})

	return nil
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
		return fmt.Errorf("failed to get AMT general settings: %w", amtPassError(err))
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
		return fmt.Errorf("failed to update AMT password: %w", amtPassError(err))
	}

	log.Trace(response)
	log.Info("Successfully updated AMT Password.")

	return nil
}

// msgAMTPass401 is the message the amtpassword command shows for any error
// that mentions 401.
const msgAMTPass401 = "Received 401 unauthorized"

// wsmanUnauthorizedMarker is the text go-wsman-messages gives an HTTP 401: it
// returns fmt.Errorf("%w: %v\n%v", errPostResponse, res.Status, body) with an
// unexported errPostResponse (pkg/wsman/client/wsman.go:531-535, v2.50.5).
//
// TODO: match a typed error once go-wsman-messages exports one for a 401.
const wsmanUnauthorizedMarker = "wsman.Client post received: 401"

// ErrAMTUnauthorized is the error the amtpassword command returns, wrapped,
// when AMT answered with HTTP 401. It carries no exit code, so the CLI's exit
// code is unchanged.
var ErrAMTUnauthorized error = &amtUnauthorizedError{}

// amtUnauthorizedError is ErrAMTUnauthorized's type: an HTTP 401 from AMT.
type amtUnauthorizedError struct{}

func (*amtUnauthorizedError) Error() string { return msgAMTPass401 }

// mentions401Error reads like ErrAMTUnauthorized but stands for any other
// error that mentions 401, such as a 500 whose body contains "401".
type mentions401Error struct{}

func (mentions401Error) Error() string { return msgAMTPass401 }

// IsWSMANUnauthorized reports whether err is go-wsman-messages' error for an
// HTTP 401 response. A 500 whose body contains "401" does not match.
func IsWSMANUnauthorized(err error) bool {
	return err != nil && strings.Contains(err.Error(), wsmanUnauthorizedMarker)
}

// amtPassError converts noisy AMT/WSMAN errors (including raw HTML bodies)
// into concise, user-friendly errors without leaking raw markup. Any error
// mentioning 401 reads "Received 401 unauthorized", but only an HTTP 401
// matches ErrAMTUnauthorized. The result never carries err's exit code.
func amtPassError(err error) error {
	if err == nil {
		return nil
	}

	if IsWSMANUnauthorized(err) {
		return ErrAMTUnauthorized
	}

	msg := err.Error()

	// Per request: stop being fancy. If we see a 401 anywhere, surface a concise message.
	if strings.Contains(strings.ToLower(msg), "401") {
		return mentions401Error{}
	}

	// Otherwise, just return the original error message.
	return errors.New(msg)
}
