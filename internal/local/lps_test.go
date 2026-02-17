/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	cryptotls "crypto/tls"
	"encoding/xml"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/authorization"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/managementpresence"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/remoteaccess"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/timesynchronization"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/userinitiatedconnection"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/wifiportconfiguration"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/common"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	amt2 "github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

type MockOSNetworker struct{}

var mockRenewDHCPLeaseerr error = nil

func (m MockOSNetworker) RenewDHCPLease() error {
	return mockRenewDHCPLeaseerr
}

// Mock the go-wsman-messages
type MockWSMAN struct{}

// AddMPS implements amt.WSMANer.
func (m MockWSMAN) AddMPS(password, mpsAddress string, port int) (response remoteaccess.AddMpServerResponse, err error) {
	panic("unimplemented")
}

// AddRemoteAccessPolicyRule implements amt.WSMANer.
func (m MockWSMAN) AddRemoteAccessPolicyRule(remoteAccessTrigger remoteaccess.Trigger, selectorValue string) (response remoteaccess.AddRemoteAccessPolicyRuleResponse, err error) {
	panic("unimplemented")
}

// GetEnvironmentDetectionSettings implements amt.WSMANer.
func (m MockWSMAN) GetEnvironmentDetectionSettings() (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error) {
	panic("unimplemented")
}

// GetMPSSAP implements amt.WSMANer.
func (m MockWSMAN) GetMPSSAP() (response []managementpresence.ManagementRemoteResponse, err error) {
	panic("unimplemented")
}

func (g MockWSMAN) GetSetupAndConfigurationService() (setupandconfiguration.Response, error) {
	panic("unimplemented")
}

// GetRemoteAccessPolicies implements amt.WSMANer.
func (m MockWSMAN) GetRemoteAccessPolicies() (response []remoteaccess.RemoteAccessPolicyAppliesToMPSResponse, err error) {
	panic("unimplemented")
}

// PutEnvironmentDetectionSettings implements amt.WSMANer.
func (m MockWSMAN) PutEnvironmentDetectionSettings(environmentDetectionSettingData environmentdetection.EnvironmentDetectionSettingDataRequest) (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error) {
	panic("unimplemented")
}

// PutRemoteAccessPolicyAppliesToMPS implements amt.WSMANer.
func (m MockWSMAN) PutRemoteAccessPolicyAppliesToMPS(policy remoteaccess.RemoteAccessPolicyAppliesToMPSResponse) (response remoteaccess.Body, err error) {
	panic("unimplemented")
}

// RequestStateChangeCIRA implements amt.WSMANer.
func (m MockWSMAN) RequestStateChangeCIRA() (response userinitiatedconnection.RequestStateChange_OUTPUT, err error) {
	panic("unimplemented")
}

// RemoveRemoteAccessPolicyRules implements amt.WSMANer.
func (m MockWSMAN) RemoveRemoteAccessPolicyRules() (err error) {
	panic("unimplemented")
}

// RemoveMPSSAP implements amt.WSMANer.
func (m MockWSMAN) RemoveMPSSAP(name string) (err error) {
	panic("unimplemented")
}

var (
	mockPutIPSIEEE8021xError    error = nil
	mockPutIPSIEEE8021xResponse ieee8021x.Response
)

func (m MockWSMAN) PutIPSIEEE8021xSettings(ieee8021xSettings *ieee8021x.IEEE8021xSettingsRequest) (response ieee8021x.Response, err error) {
	return mockPutIPSIEEE8021xResponse, mockPutIPSIEEE8021xError
}

var (
	mockSetIPSIEEE8021xError    error = nil
	mockSetIPSIEEE8021xResponse ieee8021x.Response
)

func (m MockWSMAN) SetIPSIEEE8021xCertificates(serverCertificateIssuer, clientCertificate string) (response ieee8021x.Response, err error) {
	return mockSetIPSIEEE8021xResponse, mockSetIPSIEEE8021xError
}

var mockGetIPSIEEE8021xError error = nil

func (m MockWSMAN) GetIPSIEEE8021xSettings() (response ieee8021x.Response, err error) {
	return ieee8021x.Response{
		Body: ieee8021x.Body{
			IEEE8021xSettingsResponse: ieee8021x.IEEE8021xSettingsResponse{
				InstanceID:    "wifi8021x",
				ElementName:   "8021x",
				Enabled:       3,
				AvailableInS0: true,
				PxeTimeout:    120,
			},
		},
	}, mockGetIPSIEEE8021xError
}

func (MockWSMAN) UpdateAMTPassword(passwordBase64 string) (authorization.Response, error) {
	return authorization.Response{
		Body: authorization.Body{
			SetAdminResponse: authorization.SetAdminAclEntryEx_OUTPUT{
				ReturnValue: 0,
			},
		},
	}, nil
}

var (
	mockGetIpsOptInServiceError    error = nil
	mockGetIpsOptInServiceResponse optin.Response
)

func (m MockWSMAN) GetIpsOptInService() (response optin.Response, err error) {
	return mockGetIpsOptInServiceResponse, mockGetIpsOptInServiceError
}

var (
	PutIpsOptInServiceError    error = nil
	PutIpsOptInServiceResponse optin.Response
)

func (m MockWSMAN) PutIpsOptInService(request optin.OptInServiceRequest) (response optin.Response, err error) {
	return PutIpsOptInServiceResponse, PutIpsOptInServiceError
}

var (
	mockGetRedirectionServiceError    error = nil
	mockGetRedirectionServiceResponse redirection.Response
)

func (m MockWSMAN) GetRedirectionService() (response redirection.Response, err error) {
	return mockGetRedirectionServiceResponse, mockGetRedirectionServiceError
}

var (
	mockPutRedirectionStateError    error = nil
	mockPutRedirectionStateResponse redirection.Response
)

func (m MockWSMAN) PutRedirectionState(requestedState *redirection.RedirectionRequest) (response redirection.Response, err error) {
	return mockPutRedirectionStateResponse, mockPutRedirectionStateError
}

var (
	mockRequestKVMStateChangeError    error = nil
	mockRequestKVMStateChangeResponse kvm.Response
)

func (m MockWSMAN) RequestKVMStateChange(requestedState kvm.KVMRedirectionSAPRequestStateChangeInput) (response kvm.Response, err error) {
	return mockRequestKVMStateChangeResponse, mockRequestKVMStateChangeError
}

var (
	mockRequestRedirectionStateChangeError    error = nil
	mockRequestRedirectionStateChangeResponse redirection.Response
)

func (m MockWSMAN) RequestRedirectionStateChange(requestedState redirection.RequestedState) (response redirection.Response, err error) {
	return mockRequestRedirectionStateChangeResponse, mockRequestRedirectionStateChangeError
}

var (
	PKCS10RequestError error = nil
	PKCS10Response     publickey.Response
)

func (MockWSMAN) GeneratePKCS10RequestEx(keyPair, nullSignedCertificateRequest string, signingAlgorithm publickey.SigningAlgorithm) (response publickey.Response, err error) {
	return PKCS10Response, PKCS10RequestError
}

var (
	mockCommitChangesErr         error = nil
	mockCommitChangesReturnValue int   = 0
	// mockCommitChangesErrs allows sequenced errors for retry testing.
	// When non-nil, each call pops the first element; when empty, falls back to mockCommitChangesErr.
	mockCommitChangesErrs []error = nil
)

func (m MockWSMAN) CommitChanges() (response setupandconfiguration.Response, err error) {
	if len(mockCommitChangesErrs) > 0 {
		e := mockCommitChangesErrs[0]
		mockCommitChangesErrs = mockCommitChangesErrs[1:]

		return setupandconfiguration.Response{
			Body: setupandconfiguration.Body{
				CommitChanges_OUTPUT: setupandconfiguration.CommitChanges_OUTPUT{
					ReturnValue: setupandconfiguration.ReturnValue(mockCommitChangesReturnValue),
				},
			},
		}, e
	}

	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			CommitChanges_OUTPUT: setupandconfiguration.CommitChanges_OUTPUT{
				ReturnValue: setupandconfiguration.ReturnValue(mockCommitChangesReturnValue),
			},
		},
	}, mockCommitChangesErr
}

var (
	mockCreateTLSCredentialContextErr      error = nil
	mockCreateTLSCredentialContextResponse tls.Response
)

func (m MockWSMAN) CreateTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	return mockCreateTLSCredentialContextResponse, mockCreateTLSCredentialContextErr
}

var (
	mockPutTLSCredentialContextErr      error = nil
	mockPutTLSCredentialContextResponse tls.Response
)

func (m MockWSMAN) PutTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	return mockPutTLSCredentialContextResponse, mockPutTLSCredentialContextErr
}

var (
	mockEnumerateTLSSettingDataErr error = nil
	mockTLSSettingDataContext      string
)

func (m MockWSMAN) EnumerateTLSSettingData() (response tls.Response, err error) {
	return tls.Response{
		Body: tls.Body{
			EnumerateResponse: common.EnumerateResponse{
				EnumerationContext: mockTLSSettingDataContext,
			},
		},
	}, mockEnumerateTLSSettingDataErr
}

var (
	mockGenKeyPairErr         error = nil
	mockGenKeyPairReturnValue int
	mockGenKeyPairSelectors   []publickey.SelectorResponse
)

func (m MockWSMAN) GenerateKeyPair(keyAlgorithm publickey.KeyAlgorithm, keyLength publickey.KeyLength) (response publickey.Response, err error) {
	return publickey.Response{
		Body: publickey.Body{
			GenerateKeyPair_OUTPUT: publickey.GenerateKeyPair_OUTPUT{
				ReturnValue: publickey.ReturnValue(mockGenKeyPairReturnValue),
				KeyPair: publickey.KeyPairResponse{
					ReferenceParameters: publickey.ReferenceParametersResponse{
						SelectorSet: publickey.SelectorSetResponse{
							Selectors: mockGenKeyPairSelectors,
						},
					},
				},
			},
		},
	}, mockGenKeyPairErr
}

var (
	mockPullTLSSettingDataErr   error = nil
	mockPullTLSSettingDataItems []tls.SettingDataResponse
)

func (m MockWSMAN) PullTLSSettingData(enumerationContext string) (response tls.Response, err error) {
	return tls.Response{
		Body: tls.Body{
			PullResponse: tls.PullResponse{
				SettingDataItems: mockPullTLSSettingDataItems,
			},
		},
	}, mockPullTLSSettingDataErr
}

var mockGetLowAccuracyTimeSynchRsp = timesynchronization.Response{
	Body: timesynchronization.Body{
		GetLowAccuracyTimeSynchResponse: timesynchronization.GetLowAccuracyTimeSynchResponse{
			Ta0:         time.Now().Unix(),
			ReturnValue: 0,
		},
	},
}
var mockGetLowAccuracyTimeSynchErr error = nil

func (m MockWSMAN) GetLowAccuracyTimeSynch() (response timesynchronization.Response, err error) {
	return mockGetLowAccuracyTimeSynchRsp, mockGetLowAccuracyTimeSynchErr
}

var mockSetHighAccuracyTimeSynchRsp = timesynchronization.Response{
	Body: timesynchronization.Body{
		SetHighAccuracyTimeSynchResponse: timesynchronization.SetHighAccuracyTimeSynchResponse{
			ReturnValue: 0,
		},
	},
}
var mockSetHighAccuracyTimeSynchErr error = nil

func (m MockWSMAN) SetHighAccuracyTimeSynch(ta0, tm1, tm2 int64) (response timesynchronization.Response, err error) {
	return mockSetHighAccuracyTimeSynchRsp, mockSetHighAccuracyTimeSynchErr
}

var mockDeleteKeyPairErr error = nil

func (MockWSMAN) DeleteKeyPair(instanceID string) error {
	return mockDeleteKeyPairErr
}

var (
	mockPutTLSSettingErr          error = nil
	mockPutTLSSettingDataResponse tls.Response
)

func (MockWSMAN) PUTTLSSettings(instanceID string, tlsSettingData tls.SettingDataRequest) (response tls.Response, err error) {
	return mockPutTLSSettingDataResponse, mockPutTLSSettingErr
}

var (
	mockACMUnprovisionValue       = 0
	mockACMUnprovisionErr   error = nil
)

func (m MockWSMAN) Unprovision(int) (setupandconfiguration.Response, error) {
	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			Unprovision_OUTPUT: setupandconfiguration.Unprovision_OUTPUT{
				ReturnValue: setupandconfiguration.ReturnValue(mockACMUnprovisionValue),
			},
		},
	}, mockACMUnprovisionErr
}

func (m MockWSMAN) PartialUnprovision() (setupandconfiguration.Response, error) {
	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			PartialUnprovision_OUTPUT: setupandconfiguration.PartialUnprovision_OUTPUT{
				ReturnValue: setupandconfiguration.ReturnValue(0),
			},
		},
	}, nil
}

var mockSetupAndConfigurationErr error = nil

func (m MockWSMAN) SetupMEBX(password string) (setupandconfiguration.Response, error) {
	return setupandconfiguration.Response{
		Body: setupandconfiguration.Body{
			SetMEBxPassword_OUTPUT: setupandconfiguration.SetMEBxPassword_OUTPUT{
				ReturnValue: 0,
			},
		},
	}, mockSetupAndConfigurationErr
}

var mockSetupWsmanClientErr error = nil

func (m MockWSMAN) SetupWsmanClient(username, password string, useTLS, logAMTMessages bool, tlsConfig *cryptotls.Config) error {
	return mockSetupWsmanClientErr
}

var (
	mockGeneralSettings          = general.Response{}
	errMockGeneralSettings error = nil
)

func (m MockWSMAN) GetGeneralSettings() (general.Response, error) {
	return mockGeneralSettings, errMockGeneralSettings
}

var (
	mockHostBasedSetupService       = hostbasedsetup.Response{}
	errHostBasedSetupService  error = nil
)

func (m MockWSMAN) HostBasedSetupService(digestRealm, password string) (hostbasedsetup.Response, error) {
	return mockHostBasedSetupService, errHostBasedSetupService
}

var (
	mockGetHostBasedSetupService       = hostbasedsetup.Response{}
	errGetHostBasedSetupService  error = nil
)

func (m MockWSMAN) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	return mockGetHostBasedSetupService, errGetHostBasedSetupService
}

var (
	mockAddNextCertInChain       = hostbasedsetup.Response{}
	errAddNextCertInChain  error = nil
)

func (m MockWSMAN) AddNextCertInChain(cert string, isLeaf, isRoot bool) (hostbasedsetup.Response, error) {
	return mockAddNextCertInChain, errAddNextCertInChain
}

var (
	mockHostBasedSetupServiceAdmin       = hostbasedsetup.Response{}
	errHostBasedSetupServiceAdmin  error = nil
)

func (m MockWSMAN) HostBasedSetupServiceAdmin(password, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error) {
	return mockHostBasedSetupServiceAdmin, errHostBasedSetupServiceAdmin
}

var (
	mockGetPublicKeyCertsResponse       = []publickey.RefinedPublicKeyCertificateResponse{}
	errGetPublicKeyCerts          error = nil
)

func (m MockWSMAN) GetPublicKeyCerts() ([]publickey.RefinedPublicKeyCertificateResponse, error) {
	return mockGetPublicKeyCertsResponse, errGetPublicKeyCerts
}

var (
	errGetPublicPrivateKeyPairs  error                                       = nil
	PublicPrivateKeyPairResponse []publicprivate.RefinedPublicPrivateKeyPair = nil
)

func (m MockWSMAN) GetPublicPrivateKeyPairs() ([]publicprivate.RefinedPublicPrivateKeyPair, error) {
	return PublicPrivateKeyPairResponse, errGetPublicPrivateKeyPairs
}

var errDeletePublicPrivateKeyPair error = nil

func (m MockWSMAN) DeletePublicPrivateKeyPair(instanceId string) error {
	return errDeletePublicPrivateKeyPair
}

var errDeletePublicCert error = nil

func (m MockWSMAN) DeletePublicCert(instanceId string) error {
	return errDeletePublicCert
}

var errGetCredentialRelationships error = nil

func (m MockWSMAN) GetCredentialRelationships() (credential.Items, error) {
	return credential.Items{
		CredentialContext: []credential.CredentialContext{
			{
				ElementInContext: models.AssociationReference{
					Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
					ReferenceParameters: models.ReferenceParametersNoNamespace{
						XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
						ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
						SelectorSet: models.SelectorNoNamespace{
							XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
							Selectors: []models.SelectorResponse{
								{
									XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
									Name:    "InstanceID",
									Text:    "Intel(r) AMT Certificate: Handle: 2",
								},
							},
						},
					},
				},
				ElementProvidingContext: models.AssociationReference{
					Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
					ReferenceParameters: models.ReferenceParametersNoNamespace{
						XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
						ResourceURI: "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings",
						SelectorSet: models.SelectorNoNamespace{
							XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
							Selectors: []models.SelectorResponse{
								{
									XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
									Name:    "InstanceID",
									Text:    "Intel(r) AMT:IEEE 802.1x Settings wifi8021x",
								},
							},
						},
					},
				},
			}, {
				ElementInContext: models.AssociationReference{
					Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
					ReferenceParameters: models.ReferenceParametersNoNamespace{
						XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
						ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
						SelectorSet: models.SelectorNoNamespace{
							XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
							Selectors: []models.SelectorResponse{
								{
									XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
									Name:    "InstanceID",
									Text:    "Intel(r) AMT Certificate: Handle: 1",
								},
							},
						},
					},
				},
				ElementProvidingContext: models.AssociationReference{
					Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
					ReferenceParameters: models.ReferenceParametersNoNamespace{
						XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
						ResourceURI: "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings",
						SelectorSet: models.SelectorNoNamespace{
							XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
							Selectors: []models.SelectorResponse{
								{
									XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
									Name:    "InstanceID",
									Text:    "Intel(r) AMT:IEEE 802.1x Settings wifi8021x",
								},
							},
						},
					},
				},
			},
		},
		CredentialContextTLS:   []credential.CredentialContext{},
		CredentialContext8021x: []credential.CredentialContext{},
	}, errGetCredentialRelationships
}

var errGetConcreteDependencies error = nil

func (m MockWSMAN) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	return []concrete.ConcreteDependency{
		{
			Antecedent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParametersNoNamespace{
					XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AssetTableService",
					SelectorSet: models.SelectorNoNamespace{
						XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
						Selectors: []models.SelectorResponse{
							{
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "CreationClassName",
								Text:    "AMT_AssetTableService",
							}, {
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "Name",
								Text:    "Intel(r) AMT Asset Table Service",
							}, {
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "SystemCreationClassName",
								Text:    "CIM_ComputerSystem",
							}, {
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "SystemName",
								Text:    "Intel(r) AMT",
							},
						},
					},
				},
			},
			Dependent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParametersNoNamespace{
					XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AssetTable",
					SelectorSet: models.SelectorNoNamespace{
						XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
						Selectors: []models.SelectorResponse{
							{
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "InstanceID",
								Text:    "1",
							}, {
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "TableType",
								Text:    "131",
							},
						},
					},
				},
			},
		}, {
			Antecedent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParametersNoNamespace{
					XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
					SelectorSet: models.SelectorNoNamespace{
						XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
						Selectors: []models.SelectorResponse{
							{
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "InstanceID",
								Text:    "Intel(r) AMT Certificate: Handle: 1",
							},
						},
					},
				},
			},
			Dependent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParametersNoNamespace{
					XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair",
					SelectorSet: models.SelectorNoNamespace{
						XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
						Selectors: []models.SelectorResponse{
							{
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "InstanceID",
								Text:    "Intel(r) AMT Key: Handle: 0",
							},
						},
					},
				},
			},
		}, {
			Antecedent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParametersNoNamespace{
					XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate",
					SelectorSet: models.SelectorNoNamespace{
						XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
						Selectors: []models.SelectorResponse{
							{
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "InstanceID",
								Text:    "Intel(r) AMT Certificate: Handle: 1",
							},
						},
					},
				},
			},
			Dependent: models.AssociationReference{
				Address: "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
				ReferenceParameters: models.ReferenceParametersNoNamespace{
					XMLName:     xml.Name{Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing", Local: "ReferenceParameters"},
					ResourceURI: "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SOME_UNHANDLED_RESOURCE_FOR_TESTING",
					SelectorSet: models.SelectorNoNamespace{
						XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "SelectorSet"},
						Selectors: []models.SelectorResponse{
							{
								XMLName: xml.Name{Space: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", Local: "Selector"},
								Name:    "InstanceID",
								Text:    "Intel(r) AMT Key: Handle: 0",
							},
						},
					},
				},
			},
		},
	}, errGetConcreteDependencies
}

var (
	errGetWiFiSettings      error = nil
	getWiFiSettingsResponse       = []wifi.WiFiEndpointSettingsResponse{{
		AuthenticationMethod: 0,
		BSSType:              0,
		ElementName:          "",
		EncryptionMethod:     0,
		InstanceID:           "Config1",
		Priority:             0,
		SSID:                 "",
	}, {
		AuthenticationMethod: 0,
		BSSType:              0,
		ElementName:          "",
		EncryptionMethod:     0,
		InstanceID:           "Config2",
		Priority:             0,
		SSID:                 "",
	}, {
		AuthenticationMethod: 0,
		BSSType:              0,
		ElementName:          "",
		EncryptionMethod:     0,
		InstanceID:           "",
		Priority:             0,
		SSID:                 "",
	}}
)

func (m MockWSMAN) GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error) {
	return getWiFiSettingsResponse, errGetWiFiSettings
}

var errDeleteWiFiSetting error = nil

func (m MockWSMAN) DeleteWiFiSetting(instanceId string) error {
	return errDeleteWiFiSetting
}

var errAddTrustedRootCert error = nil

func (m MockWSMAN) AddTrustedRootCert(caCert string) (string, error) {
	return "rootCertHandle", errAddTrustedRootCert
}

var errAddClientCert error = nil

func (m MockWSMAN) AddClientCert(clientCert string) (string, error) {
	return "clientCertHandle", errAddClientCert
}

var errAddPrivateKey error = nil

func (m MockWSMAN) AddPrivateKey(privateKey string) (string, error) {
	return "privateKeyHandle", errAddPrivateKey
}

var errEnableWiFi error = nil

func (m MockWSMAN) EnableWiFi(enableSync, enableWiFiSharing bool) error {
	return errEnableWiFi
}

var errAddWiFiSettings error = nil

func (m MockWSMAN) AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (wifiportconfiguration.Response, error) {
	return wifiportconfiguration.Response{}, errAddWiFiSettings
}

var (
	errGetEthernetSettings      error = nil
	getEthernetSettingsResponse       = []ethernetport.SettingsResponse{{}}
)

func (m MockWSMAN) GetEthernetSettings() ([]ethernetport.SettingsResponse, error) {
	return getEthernetSettingsResponse, errGetEthernetSettings
}

var (
	putEthernetResponse    ethernetport.Response = ethernetport.Response{}
	errPutEthernetSettings error                 = nil
)

func (m MockWSMAN) PutEthernetSettings(ethernetport.SettingsRequest, string) (ethernetport.Response, error) {
	if errPutEthernetSettings != nil {
		return ethernetport.Response{}, errPutEthernetSettings
	}

	return putEthernetResponse, nil
}

// Mock the AMT Hardware
type MockAMT struct{}

const (
	ChangeEnabledResponseNewEnabled             = 0x82
	ChangeEnabledResponseNewDisabled            = 0x80
	ChangeEnabledResponseNotNew                 = 0x00
	ChangeEnabledResponseNewTLSEnforcedEnabled  = 0xC2
	ChangeEnabledResponseNewTLSEnforcedDisabled = 0xC0
)

var (
	mockChangeEnabledResponse       = amt2.ChangeEnabledResponse(ChangeEnabledResponseNewEnabled)
	errMockChangeEnabled      error = nil
	errMockStandard                 = errors.New("failed")
)

func (c MockAMT) Initialize() error {
	return nil
}

var mockVersionDataErr error = nil

func (c MockAMT) GetVersionDataFromME(key string, amtTimeout time.Duration) (string, error) {
	return "Version", mockVersionDataErr
}

func (c MockAMT) GetChangeEnabled() (amt2.ChangeEnabledResponse, error) {
	return mockChangeEnabledResponse, errMockChangeEnabled
}

var mockEnableAMTErr error = nil

func (c MockAMT) EnableAMT() error { return mockEnableAMTErr }

var mockDisableAMTErr error = nil

func (c MockAMT) DisableAMT() error { return mockDisableAMTErr }

var (
	mockUUID          = "123-456-789"
	mockUUIDErr error = nil
)

func (c MockAMT) GetUUID() (string, error) { return mockUUID, mockUUIDErr }

var (
	mockControlMode          = 0
	mockControlModeErr error = nil
)

func (c MockAMT) GetControlMode() (int, error) { return mockControlMode, mockControlModeErr }

var (
	mockDNSSuffix          = "dns.org"
	mockDNSSuffixErr error = nil
)

func (c MockAMT) GetDNSSuffix() (string, error) { return mockDNSSuffix, mockDNSSuffixErr }

var (
	mockOSDNSSuffix          = "os.dns.org"
	mockOSDNSSuffixErr error = nil
)

func (c MockAMT) GetOSDNSSuffix() (string, error) { return mockOSDNSSuffix, mockOSDNSSuffixErr }

var mockCertHashesDefault = []amt2.CertHashEntry{
	{
		Hash:      "ABCDEFG",
		Name:      "Cert 01 Big Important CA",
		Algorithm: "SHA256",
		IsDefault: true,
	},
	{
		Hash:      "424242",
		Name:      "Cert 02 Small Important CA",
		Algorithm: "SHA256",
		IsActive:  true,
	},
	{
		Hash:      "wiggledywaggledy",
		Name:      "Cert 03 NotAtAll Important CA",
		Algorithm: "SHA256",
		IsActive:  true,
		IsDefault: true,
	},
}

var (
	mockCertHashes    []amt2.CertHashEntry
	mockCertHashesErr error = nil
)

func (c MockAMT) GetCertificateHashes() ([]amt2.CertHashEntry, error) {
	return mockCertHashes, mockCertHashesErr
}

var (
	mockRemoteAcessConnectionStatus          = amt2.RemoteAccessStatus{}
	mockRemoteAcessConnectionStatusErr error = nil
)

func (c MockAMT) GetRemoteAccessConnectionStatus() (amt2.RemoteAccessStatus, error) {
	return mockRemoteAcessConnectionStatus, mockRemoteAcessConnectionStatusErr
}

var (
	mockLANInterfaceSettings          = amt2.InterfaceSettings{}
	mockLANInterfaceSettingsErr error = nil
)

func (c MockAMT) GetLANInterfaceSettings(useWireless bool) (amt2.InterfaceSettings, error) {
	return mockLANInterfaceSettings, mockLANInterfaceSettingsErr
}

var mockLocalSystemAccountErr error = nil

func (c MockAMT) GetLocalSystemAccount() (amt2.LocalSystemAccount, error) {
	return amt2.LocalSystemAccount{Username: "Username", Password: "Password"}, mockLocalSystemAccountErr
}

var (
	mockUnprovisionCode       = 0
	mockUnprovisionErr  error = nil
)

func (c MockAMT) Unprovision() (int, error)        { return mockUnprovisionCode, mockUnprovisionErr }
func (c MockAMT) PartialUnprovision() (int, error) { return 0, nil }

func (c MockAMT) StartConfigurationHBased(amt2.SecureHBasedParameters) (amt2.SecureHBasedResponse, error) {
	return amt2.SecureHBasedResponse{}, nil
}

var mockStopConfigurationErr error = nil

func (c MockAMT) StopConfiguration() (amt2.StopConfigurationResponse, error) {
	return amt2.StopConfigurationResponse{}, mockStopConfigurationErr
}

type ResponseFuncArray []func(w http.ResponseWriter, r *http.Request)

func setupService(f *flags.Flags) ProvisioningService {
	service := NewProvisioningService(f)
	service.amtCommand = MockAMT{}
	service.networker = &MockOSNetworker{}
	service.interfacedWsmanMessage = MockWSMAN{}

	return service
}

func TestExecute(t *testing.T) {
	f := &flags.Flags{}

	t.Run("execute CommandAMTInfo should succeed", func(t *testing.T) {
		f.Command = utils.CommandAMTInfo
		rc := ExecuteCommand(f)
		assert.Equal(t, nil, rc)
	})

	t.Run("execute CommandVersion should succeed", func(t *testing.T) {
		f.Command = utils.CommandVersion
		rc := ExecuteCommand(f)
		assert.Equal(t, nil, rc)
	})

	t.Run("execute CommandConfigure with no SubCommand fails", func(t *testing.T) {
		f.Command = utils.CommandConfigure
		mockControlMode = 1
		rc := ExecuteCommand(f)
		assert.Equal(t, utils.UnableToConfigure, rc)
	})
}
