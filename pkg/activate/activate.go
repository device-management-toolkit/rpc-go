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

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	log "github.com/sirupsen/logrus"
)

var errRelativeAuthEndpoint = errors.New("AuthEndpoint must be an absolute HTTP(S) URL")

// runner is the internal activate command, run through Kong's hooks.
type runner interface {
	Validate() error
	AfterApply(amt.Interface) error
	Run(*commands.Context) error
	GetWSManClient() interfaces.WSMANer
}

// run calls the hooks in Kong's order: the CLI root's Validate, which checks
// the ServerAuthFlags in ctx, then the command's Validate, AfterApply and Run.
// It then closes the WSMAN client the command still holds, which the CLI
// leaves to process exit.
func run(cmd runner, ctx *commands.Context) error {
	if err := ctx.Validate(); err != nil {
		return err
	}

	if err := cmd.Validate(); err != nil {
		return err
	}

	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx.AMTCommand = &amtCommand

	// Read the client after Run: it is created lazily inside Run.
	defer func() { closeWSMAN(cmd.GetWSManClient()) }()

	return cmd.Run(ctx)
}

// closeWSMAN releases a WSMAN client's connection. Over LME a held connection
// keeps the MEI device open, and the next call fails with "device busy".
func closeWSMAN(client interfaces.WSMANer) {
	if client == nil {
		return
	}

	// Only log a close failure so it never replaces Run's result.
	if err := client.Close(); err != nil {
		log.Debugf("closing WSMAN client: %v", err)
	}
}

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
