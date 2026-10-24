//go:build cgo

/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"bytes"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestCaptureOutputsAndReturnPreservesNonzeroStatus(t *testing.T) {
	var output bytes.Buffer

	var errOutput bytes.Buffer

	var captured []string

	status := captureOutputsAndReturn(
		utils.AmtNotReady.Code,
		func() {
			_, _ = output.WriteString("AMT Health Check: not ready")

			captured = append(captured, "stdout")
		},
		func() {
			_, _ = errOutput.WriteString("Error 4: AmtNotReady")

			captured = append(captured, "stderr")
		},
	)

	assert.Equal(t, utils.AmtNotReady.Code, status)
	assert.Equal(t, "AMT Health Check: not ready", output.String())
	assert.Equal(t, "Error 4: AmtNotReady", errOutput.String())
	assert.Equal(t, []string{"stdout", "stderr"}, captured)
}
