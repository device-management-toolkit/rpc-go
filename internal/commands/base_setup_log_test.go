/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"testing"
	"time"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAMTBaseCmd_AfterApplyLocalTLSNotice(t *testing.T) {
	const tlsEnforced = amt.ChangeEnabledResponse(0x40)

	tests := []struct {
		name      string
		quiet     bool
		wantLevel logrus.Level
	}{
		{name: "shown for commands that do not report it", quiet: false, wantLevel: logrus.InfoLevel},
		{name: "debug only for commands that report it", quiet: true, wantLevel: logrus.DebugLevel},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			amtCommand := mock.NewMockInterface(ctrl)
			amtCommand.EXPECT().Close().Return(nil)
			amtCommand.EXPECT().GetControlMode().Return(1, nil)
			amtCommand.EXPECT().GetChangeEnabled().Return(tlsEnforced, nil)

			hook := logtest.NewGlobal()
			defer hook.Reset()

			originalLevel := logrus.GetLevel()
			defer logrus.SetLevel(originalLevel)

			logrus.SetLevel(logrus.DebugLevel)

			cmd := &AMTBaseCmd{QuietSetupLogs: tt.quiet}
			require.NoError(t, cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) {}))
			assert.True(t, cmd.LocalTLSEnforced)
			assert.True(t, cmd.LocalTLSStatusRead)

			var levels []logrus.Level

			for _, entry := range hook.AllEntries() {
				if entry.Message == "TLS is enforced on local ports" {
					levels = append(levels, entry.Level)
				}
			}

			assert.Equal(t, []logrus.Level{tt.wantLevel}, levels)
		})
	}
}

func TestAMTBaseCmd_AfterApplyLocalTLSStatusReadFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	amtCommand := mock.NewMockInterface(ctrl)
	amtCommand.EXPECT().Close().Return(nil)
	amtCommand.EXPECT().GetControlMode().Return(1, nil)
	amtCommand.EXPECT().GetChangeEnabled().Return(amt.ChangeEnabledResponse(0), errors.New("HECI busy"))

	cmd := &AMTBaseCmd{}
	require.NoError(t, cmd.afterApply(amtCommand, true, "amd64", func(time.Duration) {}))

	assert.False(t, cmd.LocalTLSEnforced)
	assert.False(t, cmd.LocalTLSStatusRead, "a failed read must not look like a known 'not enforced'")
}

func TestAmtInfoCmd_BeforeApplyQuietsSetupLogs(t *testing.T) {
	cmd := &AmtInfoCmd{}

	require.NoError(t, cmd.BeforeApply())
	assert.True(t, cmd.QuietSetupLogs)
}
