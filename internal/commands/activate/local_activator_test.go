/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package activate

import (
	"errors"
	"os"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/commands/drive"
	"github.com/device-management-toolkit/rpc-go/v2/internal/orchestrator"
	"github.com/stretchr/testify/require"
)

var errActivationFailed = errors.New("activation failed")

func TestMain(m *testing.M) {
	// The real driveRun activates this device; no test in this package may
	// reach it.
	driveRun = func(drive.Runner, *commands.Context) error {
		panic("test reached the real drive.Run")
	}

	os.Exit(m.Run())
}

// stubDriveRun records the command and context localActivator drives and
// returns err.
func stubDriveRun(t *testing.T, err error) (*[]drive.Runner, *[]*commands.Context) {
	t.Helper()

	var (
		cmds []drive.Runner
		ctxs []*commands.Context
	)

	orig := driveRun
	driveRun = func(cmd drive.Runner, ctx *commands.Context) error {
		cmds = append(cmds, cmd)
		ctxs = append(ctxs, ctx)

		return err
	}

	t.Cleanup(func() { driveRun = orig })

	return &cmds, &ctxs
}

func TestLocalActivator_MapsActivation(t *testing.T) {
	tests := []struct {
		name    string
		outer   *ActivateCmd
		in      orchestrator.LocalActivation
		wantCmd *ActivateCmd
		wantCtx *commands.Context
	}{
		{
			name:  "ACM",
			outer: &ActivateCmd{SkipIPRenew: true},
			in: orchestrator.LocalActivation{
				ACM:                      true,
				ProvisioningCert:         "cert-data",
				ProvisioningCertPassword: "cert-pwd",
				AMTPassword:              "admin-pwd",
				MEBxPassword:             "mebx-pwd",
				SkipAMTCertCheck:         true,
			},
			wantCmd: &ActivateCmd{
				Local:               true,
				ACM:                 true,
				ProvisioningCert:    "cert-data",
				ProvisioningCertPwd: "cert-pwd",
				MEBxPassword:        "mebx-pwd",
				SkipIPRenew:         true,
			},
			// No Console auth flags: unlike the old child, which inherited
			// AUTH_* env and registered a second time, the nested activation
			// never touches Console; the outer flow registers once.
			wantCtx: &commands.Context{AMTPassword: "admin-pwd", SkipAMTCertCheck: true},
		},
		{
			name:    "CCM",
			outer:   &ActivateCmd{},
			in:      orchestrator.LocalActivation{AMTPassword: "admin-pwd"},
			wantCmd: &ActivateCmd{Local: true, CCM: true},
			wantCtx: &commands.Context{AMTPassword: "admin-pwd"},
		},
		{
			name:    "CCM inherits SkipIPRenew",
			outer:   &ActivateCmd{SkipIPRenew: true},
			in:      orchestrator.LocalActivation{AMTPassword: "admin-pwd"},
			wantCmd: &ActivateCmd{Local: true, CCM: true, SkipIPRenew: true},
			wantCtx: &commands.Context{AMTPassword: "admin-pwd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds, ctxs := stubDriveRun(t, nil)

			require.NoError(t, tt.outer.localActivator(tt.in))

			require.Equal(t, []drive.Runner{tt.wantCmd}, *cmds)
			require.Equal(t, []*commands.Context{tt.wantCtx}, *ctxs)
		})
	}
}

func TestLocalActivator_ReturnsDriveError(t *testing.T) {
	stubDriveRun(t, errActivationFailed)

	require.ErrorIs(t, (&ActivateCmd{}).localActivator(orchestrator.LocalActivation{}), errActivationFailed)
}
