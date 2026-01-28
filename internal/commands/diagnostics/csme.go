/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

// CSMECmd dumps CSME / firmware flash diagnostics.
type CSMECmd struct {
	DiagnosticsBaseCmd
}

// Run executes the CSME diagnostics command.
func (cmd *CSMECmd) Run(ctx *commands.Context) error {
	return nil
}
