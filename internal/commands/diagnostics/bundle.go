/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

// BundleCmd collects a full diagnostics bundle.
type BundleCmd struct {
	DiagnosticsBaseCmd
}

// Run executes the diagnostics bundle collection command.
func (cmd *BundleCmd) Run(ctx *commands.Context) error {
	return nil
}
