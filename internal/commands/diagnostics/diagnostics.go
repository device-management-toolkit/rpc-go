/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

package diagnostics

import (
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
)

// DiagnosticsBaseCmd provides base functionality for all diagnostics commands.
type DiagnosticsBaseCmd struct {
	commands.AMTBaseCmd
}

// DiagnosticsCmd is the main diagnostics command that contains all subcommands.
type DiagnosticsCmd struct {
	CIRA   CIRACmd   `cmd:"cira"   help:"Dump CIRA-related diagnostics"`
	CSME   CSMECmd   `cmd:"csme"   help:"Dump CSME / firmware flash diagnostics"`
	WSMan  WSManCmd  `cmd:"wsman" aliases:"ws-man" help:"Dump AMT WSMAN class(es)"`
	Bundle BundleCmd `cmd:"bundle" help:"Collect a full diagnostics bundle"`
}
