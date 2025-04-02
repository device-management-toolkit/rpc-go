/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"

	"github.com/stretchr/testify/assert"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
)

func setupProvisioningService() (ProvisioningService, *MockAMT, *MockWSMAN) {
	f := &flags.Flags{}
	mockAMT := new(MockAMT)
	mockWsman := new(MockWSMAN)
	service := NewProvisioningService(f)
	service.amtCommand = mockAMT
	service.interfacedWsmanMessage = mockWsman
	return service, mockAMT, mockWsman
}

var tlsSettingDataItems = []tls.SettingDataResponse{
	{
		AcceptNonSecureConnections: true,
		ElementName:                `TLS Settings`,
		Enabled:                    true,
		InstanceID:                 `Intel(r) AMT 802.3 TLS Settings`,
		MutualAuthentication:       false,
	},
	{
		AcceptNonSecureConnections: true,
		ElementName:                `TLS Settings`,
		Enabled:                    true,
		InstanceID:                 `Intel(r) AMT LMS TLS Settings`,
		MutualAuthentication:       false,
	},
}

var publicPrivateKeyPair = []publicprivate.RefinedPublicPrivateKeyPair{
	{
		ElementName: "SomeElement",
		InstanceID:  "keyHandle",
		DERKey: `MIIBCgKCAQEAydspbzaCi8omRjqHKJnuXBJ0BInNlZR22lqy40f/6r4UGpDnAuFt` +
			`yQZ0kWpJp1nfzCk60qgiBKFI2sw5cKTbBDu8n+8GQZ4yvge9//E88salGBBsDpA/` +
			`tkpoQIrlj8MQImZxPRkg0noQz53C3QKvsIgeKsraO5BX2h6iwLiynk0Nqa0ORwMI` +
			`1x3oTNRX5it24uAA2812mJBpcJE8kU4Dgb6bsw4WzTF0drY1WaKHbva18Pwu1VUa` +
			`5H7JDDIbKiS5y+FbkmBQtoiQBQ5jsfoOnecQFnuHGSANjz/ar3IbQo1vSb+uBd3l` +
			`aDrhMwfv8970gsTqUk/xiY+CYdFamjfpSQIDAQAB`,
	},
}

func TestConfigureTLSWithEA(t *testing.T) {
	tests := []struct {
		name               string
		setupMocks         func(*MockWSMAN)
		mockauthResponse   AuthResponse
		mockconfigResponse EAProfile
		mockauthError      bool
		mockconfigError    bool
		expectError        bool
	}{
		{
			name: "Successful TLS configuration",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = nil
			},
			mockauthResponse: AuthResponse{Token: "someToken"},
			mockconfigResponse: EAProfile{
				NodeID:       "someID",
				Domain:       "someDomain",
				ReqID:        "someReqID",
				AuthProtocol: 0,

				OSName:  "win11",
				DevName: "someDevName",
				Icon:    1,
				Ver:     "someVer",
				Response: Response{
					CSR:           "someCSR",
					KeyInstanceId: "someKeyInstanceID",
					AuthProtocol:  0,
					Certificate:   "someCertificate",
					Domain:        "someDomain",
					Username:      "someUsername",
				},
			},
			expectError: false,
		},
		{
			name:          "Failed to get auth token",
			setupMocks:    func(mock *MockWSMAN) {},
			mockauthError: true,
			expectError:   true,
		},
		{
			name:            "Failed to make request to EA",
			setupMocks:      func(mock *MockWSMAN) {},
			mockauthError:   false,
			mockconfigError: true,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/authenticate/") {
					if tt.expectError {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						json.NewEncoder(w).Encode(tt.mockauthResponse)
					}
				} else if strings.HasPrefix(r.URL.Path, "/api/configure/") {
					if tt.expectError {
						w.WriteHeader(http.StatusInternalServerError)
					} else {
						json.NewEncoder(w).Encode(tt.mockconfigResponse)
					}
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))

			service.flags.ConfigTLSInfo.EAAddress = server.URL
			service.flags.ConfigTLSInfo.EAUsername = "user"
			service.flags.ConfigTLSInfo.EAPassword = "pass"

			err := service.ConfigureTLSWithEA()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			// Clean up
			server.Close()
		})
	}
}

func TestConfigureTLSWithSelfSignedCert(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "Failure in AddTrustedRootCert",
			setupMocks: func(mock *MockWSMAN) {
				errAddTrustedRootCert = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Failure in GenerateKeyPair",
			setupMocks: func(mock *MockWSMAN) {
				errAddTrustedRootCert = nil
				mockGenKeyPairErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Failure to GetDERKey",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle1"}}
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
			},
			expectedError: utils.TLSConfigurationFailed,
		},
		{
			name: "Failure in AddClientCert",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = assert.AnError
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
			},
			expectedError: assert.AnError,
		},
		{
			name: "Failure in CreateTLSCredentialContext",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
				errAddClientCert = nil
				PublicPrivateKeyPairResponse = publicPrivateKeyPair
				mockCreateTLSCredentialContextErr = assert.AnError
			},
			expectedError: utils.TLSConfigurationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			err := service.ConfigureTLSWithSelfSignedCert()
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockWSMAN)
		expectedHandle string
		expectedError  error
	}{
		{
			name: "Successful key pair generation",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{{Name: "", Text: "keyHandle"}}
			},
			expectedHandle: "keyHandle",
			expectedError:  nil,
		},
		{
			name: "Error from GenerateKeyPair call",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
		{
			name: "Non-zero ReturnValue",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairErr = nil
				mockGenKeyPairReturnValue = 1
				mockGenKeyPairSelectors = []publickey.SelectorResponse{}
			},
			expectedError: utils.AmtPtStatusCodeBase,
		},
		{
			name: "Empty handle list",
			setupMocks: func(mock *MockWSMAN) {
				mockGenKeyPairReturnValue = 0
				mockGenKeyPairSelectors = []publickey.SelectorResponse{}
			},
			expectedError: utils.TLSConfigurationFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			handle, err := service.GenerateKeyPair()
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err, "Expected no error")
				assert.Equal(t, tt.expectedHandle, handle)
			}
		})
	}
}
func TestGetDERKey(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockWSMAN)
		handles        Handles
		expectedDERKey string
		expectError    bool
	}{
		{
			name: "success - matching key pair found",
			setupMocks: func(mock *MockWSMAN) {
				PublicPrivateKeyPairResponse = []publicprivate.RefinedPublicPrivateKeyPair{{InstanceID: "keyPair1", DERKey: "DERKey1", ElementName: "keyPair1"}}
			},
			handles:        Handles{keyPairHandle: "keyPair1"},
			expectedDERKey: "DERKey1",
			expectError:    false,
		},
		{
			name: "failure - no matching key pair",
			setupMocks: func(mock *MockWSMAN) {
				PublicPrivateKeyPairResponse = []publicprivate.RefinedPublicPrivateKeyPair{{InstanceID: "keyPair1", DERKey: "DERKey1", ElementName: "keyPair1"}}
			},
			handles:        Handles{keyPairHandle: "keyPair2"},
			expectedDERKey: "",
			expectError:    false,
		},
		{
			name: "failure - error fetching key pairs",
			setupMocks: func(mock *MockWSMAN) {
				PublicPrivateKeyPairResponse = []publicprivate.RefinedPublicPrivateKeyPair{}
				errGetPublicPrivateKeyPairs = assert.AnError
			},
			handles:        Handles{keyPairHandle: "keyPair1"},
			expectedDERKey: "",
			expectError:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			derKey, err := service.GetDERKey(tt.handles)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDERKey, derKey)
			}
		})
	}
}
func TestCreateTLSCredentialContext(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "successful context creation",
			setupMocks: func(mock *MockWSMAN) {
				mockCreateTLSCredentialContextErr = nil
				mockCreateTLSCredentialContextResponse = tls.Response{}
			},
			expectedError: nil,
		},
		{
			name: "context already exists",
			setupMocks: func(mock *MockWSMAN) {
				mockCreateTLSCredentialContextErr = fmt.Errorf("The context alreadyExists")
			},
			expectedError: nil,
		},
		{
			name: "WSMAN message error",
			setupMocks: func(mock *MockWSMAN) {
				mockCreateTLSCredentialContextErr = fmt.Errorf("Some WSMAN error")
			},
			expectedError: utils.WSMANMessageError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			err := service.CreateTLSCredentialContext("dummyCertHandle")
			if tt.expectedError != nil {
				assert.Equal(t, tt.expectedError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
func TestEnableTLS(t *testing.T) {

	tests := []struct {
		name          string
		setupMocks    func(*MockWSMAN)
		expectedError error
	}{
		{
			name: "Successful TLS Enablement",
			setupMocks: func(mock *MockWSMAN) {
				mockEnumerateTLSSettingDataErr = nil
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataErr = nil
				mockPullTLSSettingDataItems = tlsSettingDataItems
			},
			expectedError: nil,
		},
		{
			name: "Enumeration Failure",
			setupMocks: func(mock *MockWSMAN) {
				mockEnumerateTLSSettingDataErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Pull TLS Setting Data Failure",
			setupMocks: func(mock *MockWSMAN) {
				mockEnumerateTLSSettingDataErr = nil
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Configure TLS Setting Failure for Remote TLS Instance",
			setupMocks: func(mock *MockWSMAN) {
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataErr = nil
				mockPullTLSSettingDataItems = tlsSettingDataItems
				mockPutTLSSettingErr = assert.AnError
			},
			expectedError: utils.WSMANMessageError,
		},
		{
			name: "Commit Changes Failure",
			setupMocks: func(mock *MockWSMAN) {
				mockTLSSettingDataContext = "testContext"
				mockPullTLSSettingDataItems = tlsSettingDataItems
				mockPutTLSSettingErr = nil
				mockCommitChangesErr = assert.AnError
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, mockWsman := setupProvisioningService()
			tt.setupMocks(mockWsman)
			err := service.EnableTLS()
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
