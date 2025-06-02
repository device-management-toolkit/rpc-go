/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package local

import (
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var getRedirectionResponse = redirection.Response{
	Body: redirection.Body{
		GetAndPutResponse: redirection.RedirectionResponse{
			CreationClassName:       `AMT_RedirectionService`,
			ElementName:             `Intel(r) AMT Redirection Service`,
			EnabledState:            32771,
			ListenerEnabled:         true,
			Name:                    `Intel(r) AMT Redirection Service`,
			SystemCreationClassName: `CIM_ComputerSystem`,
			SystemName:              `Intel(r) AMT`,
			AccessLog:               nil,
		},
	},
}
var requestRedirectionStateChangeResponse = redirection.Response{
	Body: redirection.Body{
		RequestStateChange_OUTPUT: redirection.RequestStateChange_OUTPUT{
			ReturnValue: 0,
		},
	},
}

var getIpsOptInServiceResponse = optin.Response{
	Body: optin.Body{
		GetAndPutResponse: optin.OptInServiceResponse{
			CanModifyOptInPolicy:    1,
			CreationClassName:       `IPS_OptInService`,
			ElementName:             `Intel(r) AMT OptIn Service`,
			Name:                    `Intel(r) AMT OptIn Service`,
			OptInCodeTimeout:        120,
			OptInDisplayTimeout:     300,
			OptInRequired:           4294967295,
			OptInState:              0,
			SystemCreationClassName: `CIM_ComputerSystem`,
			SystemName:              `Intel(r) AMT`,
		},
	},
}

func TestSetAMTFeatures(t *testing.T) {
	tests := []struct {
		name          string
		flags         *flags.Flags // Assuming this struct defines the flags like KVM, SOL, IDER, and UserConsent
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "Error getting redirection state",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Error setting redirection service",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceError = nil
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Error setting redirection service",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeError = nil
				mockRequestRedirectionStateChangeResponse = requestRedirectionStateChangeResponse
				mockPutRedirectionStateError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Error setting KVM state",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeResponse = requestRedirectionStateChangeResponse
				mockRequestKVMStateChangeError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Error setting redirection service",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeResponse = requestRedirectionStateChangeResponse
				mockRequestKVMStateChangeError = nil
				mockRequestKVMStateChangeResponse = kvm.Response{}
				mockPutRedirectionStateError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Error getting OptIn Service",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
				ControlMode: 2,
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeResponse = requestRedirectionStateChangeResponse
				mockRequestKVMStateChangeResponse = kvm.Response{}
				mockPutRedirectionStateError = nil
				mockGetIpsOptInServiceError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Error putting OptIn Service",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "none",
				Password:    "P@ssw0rd",
				ControlMode: 2,
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeResponse = requestRedirectionStateChangeResponse
				mockRequestKVMStateChangeResponse = kvm.Response{}
				mockGetIpsOptInServiceError = nil
				mockGetIpsOptInServiceResponse = getIpsOptInServiceResponse
				PutIpsOptInServiceError = assert.AnError
			},
			expectedError: utils.AMTFeaturesConfigurationFailed,
		},
		{
			name: "Success",
			flags: &flags.Flags{
				KVM:         true,
				SOL:         true,
				IDER:        true,
				UserConsent: "all",
				Password:    "P@ssw0rd",
			},
			setupMocks: func(mock *MockWSMAN) {
				mockGetRedirectionServiceResponse = getRedirectionResponse
				mockRequestRedirectionStateChangeError = nil
				mockRequestRedirectionStateChangeResponse = requestRedirectionStateChangeResponse
				mockGetIpsOptInServiceResponse = getIpsOptInServiceResponse
			},
			expectedError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.flags
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman
			tc.setupMocks(mockWsman)

			err := service.SetAMTFeatures()
			if tc.expectedError != nil {
				assert.Equal(t, tc.expectedError, err)
			} else {
				assert.NoError(t, err, "Expected no error")
			}
		})
	}
}
