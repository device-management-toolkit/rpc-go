/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestActivateCmd_ExecutableIsNotACLIFlag(t *testing.T) {
	// Profile steps run Executable, so only library callers may set it: a flag
	// would also let an RPC_EXECUTABLE variable or config.yaml redirect them.
	var cli struct {
		Activate ActivateCmd `cmd:""`
	}

	parser, err := kong.New(&cli, kong.DefaultEnvars("RPC"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"activate", "--executable", "/tmp/not-rpc"})
	require.ErrorContains(t, err, "unknown flag --executable")
}
