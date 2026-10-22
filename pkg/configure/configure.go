/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package configure provides a public API for AMT configuration operations.
package configure

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	log "github.com/sirupsen/logrus"
)

// BaseOptions holds options shared by all configure subcommands.
type BaseOptions struct {
	// AMTPassword is the admin password for the AMT device.
	// Required for commands that need WSMAN access.
	// If empty, the user will be prompted on stdin.
	AMTPassword string
	// SkipAMTCertCheck skips TLS certificate verification when connecting to AMT.
	SkipAMTCertCheck bool
}

// runner is any internal configure command that can be run through Kong's hooks.
type runner interface {
	Validate() error
	AfterApply(amt.Interface) error
	Run(*commands.Context) error
	GetWSManClient() interfaces.WSMANer
}

// run calls the command's hooks in Kong's order: Validate, AfterApply, then Run.
// It then closes the WSMAN client Run opened, which the CLI leaves to process exit.
func run(cmd runner, opts BaseOptions) error {
	if err := cmd.Validate(); err != nil {
		return err
	}

	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx := &commands.Context{
		AMTCommand:       &amtCommand,
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
	}

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
