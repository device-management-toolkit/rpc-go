//go:build !windows && !linux

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"io"
	"os"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAmtInfoCmd_Run_NoHECIPlatform_ReportsDriverNotDetected(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cmd := &AmtInfoCmd{Hostname: true}
	ctx := &Context{AMTCommand: mock.NewMockInterface(ctrl)}

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	runErr := cmd.Run(ctx)

	w.Close()

	out, _ := io.ReadAll(r)
	os.Stdout = oldStdout

	require.NoError(t, runErr)
	assert.Contains(t, string(out), "MEI/HECI driver not detected")
	assert.NotContains(t, string(out), "Not running as administrator")
}
