/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package drive runs an rpc command outside the CLI, calling the Kong hooks
// the CLI would call. pkg/activate and the profile orchestrator's activation
// step both drive the activate command through it.
package drive

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	log "github.com/sirupsen/logrus"
)

// Runner is the internal activate command, run through Kong's hooks.
type Runner interface {
	Validate() error
	AfterApply(amt.Interface) error
	Run(*commands.Context) error
	GetWSManClient() interfaces.WSMANer
}

// Run calls the hooks in Kong's order: the CLI root's Validate, which checks
// the ServerAuthFlags in ctx, then the command's Validate, AfterApply and Run.
// It then closes the WSMAN client the command still holds, which the CLI
// leaves to process exit.
func Run(cmd Runner, ctx *commands.Context) error {
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
