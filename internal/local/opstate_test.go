/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCheckAndEnableAMT(t *testing.T) {
	errMockTimeout := errors.New("wait timeout while sending data")

	tests := []struct {
		name             string
		skipIPRenewal    bool
		expectedRC       error
		expectedTLS      bool
		rsp              amt.ChangeEnabledResponse
		errChangeEnabled error
		errEnableAMT     error
		errDisableAMT    error
		renewDHCPLeaseRC error
	}{
		{
			name:             "expect AMTConnectionFailed",
			expectedRC:       utils.AMTConnectionFailed,
			errChangeEnabled: errMockStandard,
		},
		{
			name:       "expect noop for older versions",
			expectedRC: nil,
			rsp:        ChangeEnabledResponseNotNew,
		},
		{
			name:       "expect noop if already enabled",
			expectedRC: nil,
			rsp:        ChangeEnabledResponseNewEnabled,
		},
		{
			name:        "expect 1 if TLS is enforced",
			expectedRC:  nil,
			expectedTLS: true,
			rsp:         ChangeEnabledResponseNewTLSEnforcedEnabled,
		},
		{
			name:         "expect AmtNotReady for enable if error occurs",
			expectedRC:   utils.AmtNotReady,
			rsp:          ChangeEnabledResponseNewDisabled,
			errEnableAMT: errMockStandard,
		},
		{
			name:       "expect Success for enable happy path",
			expectedRC: nil,
			rsp:        ChangeEnabledResponseNewDisabled,
		},
		{
			name:             "expect Success if skipIPRenewal is true",
			expectedRC:       nil,
			rsp:              ChangeEnabledResponseNewDisabled,
			skipIPRenewal:    true,
			renewDHCPLeaseRC: utils.WiredConfigurationFailed,
		},
		{
			name:             "expect tlsIsEnforced false when operation times out",
			expectedRC:       nil,
			expectedTLS:      false,
			errChangeEnabled: errMockTimeout,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origChangeEnabledErr := errMockChangeEnabled
			errMockChangeEnabled = tc.errChangeEnabled
			origDisableAMTErr := mockDisableAMTErr
			mockDisableAMTErr = tc.errDisableAMT
			origEnableAMTErr := mockEnableAMTErr
			mockEnableAMTErr = tc.errEnableAMT
			origRsp := mockChangeEnabledResponse
			mockChangeEnabledResponse = tc.rsp
			origRenewDHCPLeaseRC := mockRenewDHCPLeaseerr
			mockRenewDHCPLeaseerr = tc.renewDHCPLeaseRC
			f := &flags.Flags{}
			lps := setupService(f)
			err := lps.CheckAndEnableAMT(tc.skipIPRenewal)
			assert.Equal(t, tc.expectedRC, err)
			// Reset mocks
			mockChangeEnabledResponse = origRsp
			errMockChangeEnabled = origChangeEnabledErr
			mockEnableAMTErr = origEnableAMTErr
			mockDisableAMTErr = origDisableAMTErr
			mockRenewDHCPLeaseerr = origRenewDHCPLeaseRC
		})
	}
}

func TestRenewIP(t *testing.T) {
	f := &flags.Flags{}

	log.SetLevel(log.DebugLevel)

	lps := setupService(f)
	origRC := mockRenewDHCPLeaseerr
	mockRenewDHCPLeaseerr = utils.WiredConfigurationFailed
	err := lps.RenewIP()
	assert.Equal(t, mockRenewDHCPLeaseerr, err)
	mockRenewDHCPLeaseerr = origRC
}
