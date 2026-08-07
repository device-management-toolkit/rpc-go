/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/stretchr/testify/assert"
)

// TestClassifyLMSError pins the relay's error triage. The regression this guards
// against: a read timeout with no bytes (lm.ErrLMSReadTimeoutNoData) is a benign
// quiet round — AMT acknowledging a WSMAN request such as the activating Setup
// without an immediate reply — and must NOT fail the activation on the plain
// (non-TLS-tunnel) RPS relay. Genuine LMS errors must still classify as fatal.
func TestClassifyLMSError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want lmsErrorClass
	}{
		{"heci poll timeout", heci.ErrReadTimeout, lmsErrorPoll},
		{"wrapped heci poll timeout", fmt.Errorf("polling: %w", heci.ErrReadTimeout), lmsErrorPoll},
		{"quiet round no data", lm.ErrLMSReadTimeoutNoData, lmsErrorQuietRound},
		{"wrapped quiet round no data", fmt.Errorf("listen: %w", lm.ErrLMSReadTimeoutNoData), lmsErrorQuietRound},
		{"genuine lms error is fatal", errors.New("connection reset by peer"), lmsErrorFatal},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyLMSError(tt.err))
		})
	}
}
