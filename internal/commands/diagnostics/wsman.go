/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

// WSManCmd dumps AMT WSMAN diagnostic classes.
type WSManCmd struct {
	DiagnosticsBaseCmd
}

// Run executes the WSMAN diagnostics command.
func (cmd *WSManCmd) Run(ctx *commands.Context) error {
	return nil
}
