/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"errors"
	"testing"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"

	"github.com/stretchr/testify/assert"
)

func TestSynchronizeTime(t *testing.T) {
	tests := []struct {
		name                            string
		mockGetLowAccuracyTimeSynchErr  error
		mockSetHighAccuracyTimeSynchErr error
		expectedError                   bool
	}{
		{
			name:          "successful synchronization",
			expectedError: false,
		},
		{
			name:                           "failure on GetLowAccuracyTimeSynch",
			mockGetLowAccuracyTimeSynchErr: errors.New("network error"),
			expectedError:                  true,
		},
		{
			name:                            "failure on SetHighAccuracyTimeSynch",
			mockSetHighAccuracyTimeSynchErr: errors.New("network error"),
			expectedError:                   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			mockGetLowAccuracyTimeSynchErr = tc.mockGetLowAccuracyTimeSynchErr
			mockSetHighAccuracyTimeSynchErr = tc.mockSetHighAccuracyTimeSynchErr

			err := service.SynchronizeTime()

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
