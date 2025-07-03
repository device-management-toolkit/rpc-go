/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package flags

import (
	"strings"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestParseFlagsAmtInfo(t *testing.T) {
	defaultFlags := AmtInfoFlags{
		Ver:      true,
		Bld:      true,
		Sku:      true,
		UUID:     true,
		Mode:     true,
		DNS:      true,
		Ras:      true,
		Lan:      true,
		Hostname: true,
		OpState:  true,
	}

	tests := map[string]struct {
		cmdLine    string
		wantResult error
		wantFlags  AmtInfoFlags
	}{
		"expect success for basic command": {
			cmdLine:    "./rpc amtinfo -json",
			wantResult: nil,
			wantFlags:  defaultFlags,
		},
		"expect IncorrectCommandLineParameters on Parse error": {
			cmdLine:    "./rpc amtinfo -balderdash",
			wantResult: utils.IncorrectCommandLineParameters,
			wantFlags:  AmtInfoFlags{},
		},
		"expect only cert flag with no password on command line": {
			cmdLine:    "./rpc amtinfo -cert",
			wantResult: nil,
			wantFlags: AmtInfoFlags{
				Cert: true,
			},
		},
		"expect both cert flags with no password on command line": {
			cmdLine:    "./rpc amtinfo -cert -password testPassword",
			wantResult: nil,
			wantFlags: AmtInfoFlags{
				Cert:     true,
				UserCert: true,
			},
		},
		"expect success for userCert with no password": {
			cmdLine:    "./rpc amtinfo -userCert",
			wantResult: nil,
			wantFlags: AmtInfoFlags{
				UserCert: true,
			},
		},
		"expect Success for userCert with password": {
			cmdLine:    "./rpc amtinfo -userCert -password testPassword",
			wantResult: nil,
			wantFlags: AmtInfoFlags{
				UserCert: true,
			},
		},
		"expect Success for userCert with password input": {
			cmdLine:    "./rpc amtinfo -userCert",
			wantResult: nil,
			wantFlags: AmtInfoFlags{
				UserCert: true,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			args := strings.Fields(tc.cmdLine)
			flags := NewFlags(args, MockPRSuccess)
			gotResult := flags.ParseFlags()
			assert.Equal(t, tc.wantResult, gotResult)
			assert.Equal(t, true, flags.Local)
			assert.Equal(t, utils.CommandAMTInfo, flags.Command)
			assert.Equal(t, tc.wantFlags, flags.AmtInfo)
		})
	}
}
