/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

// Package configure provides a public API for AMT configuration operations.
package configure

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
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

// runner is any internal configure command that can be run with AfterApply + Run.
type runner interface {
	AfterApply(amt.Interface) error
	Run(*commands.Context) error
}

// run handles the common boilerplate: create AMTCommand, AfterApply, build Context, Run.
func run(cmd runner, opts BaseOptions) error {
	commands.DefaultSkipAMTCertCheck = opts.SkipAMTCertCheck

	amtCommand := amt.NewAMTCommand()

	if err := cmd.AfterApply(&amtCommand); err != nil {
		return err
	}

	ctx := &commands.Context{
		AMTCommand:       &amtCommand,
		AMTPassword:      opts.AMTPassword,
		SkipAMTCertCheck: opts.SkipAMTCertCheck,
	}

	return cmd.Run(ctx)
}
