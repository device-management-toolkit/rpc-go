/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package interfaces

import (
	cryptotls "crypto/tls"

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
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
)

type WSMANer interface {
	SetupWsmanClient(username, password string, useTLS, logAMTMessages bool, tlsConfig *cryptotls.Config) error
	Unprovision(int) (setupandconfiguration.Response, error)
	PartialUnprovision() (setupandconfiguration.Response, error)
	GetGeneralSettings() (general.Response, error)
	HostBasedSetupService(digestRealm, password string) (hostbasedsetup.Response, error)
	GetHostBasedSetupService() (hostbasedsetup.Response, error)
	AddNextCertInChain(cert string, isLeaf, isRoot bool) (hostbasedsetup.Response, error)
	HostBasedSetupServiceAdmin(password, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error)
	SetupMEBX(string) (response setupandconfiguration.Response, err error)
	GetSetupAndConfigurationService() (setupandconfiguration.Response, error)
	GetPublicKeyCerts() ([]publickey.RefinedPublicKeyCertificateResponse, error)
	GetPublicPrivateKeyPairs() ([]publicprivate.RefinedPublicPrivateKeyPair, error)
	DeletePublicPrivateKeyPair(instanceId string) error
	DeletePublicCert(instanceId string) error
	GetCredentialRelationships() (credential.Items, error)
	GetConcreteDependencies() ([]concrete.ConcreteDependency, error)
	AddTrustedRootCert(caCert string) (string, error)
	AddClientCert(clientCert string) (string, error)
	AddPrivateKey(privateKey string) (string, error)
	DeleteKeyPair(instanceID string) error
	GetLowAccuracyTimeSynch() (response timesynchronization.Response, err error)
	SetHighAccuracyTimeSynch(ta0, tm1, tm2 int64) (response timesynchronization.Response, err error)
	GenerateKeyPair(keyAlgorithm publickey.KeyAlgorithm, keyLength publickey.KeyLength) (response publickey.Response, err error)
	UpdateAMTPassword(passwordBase64 string) (authorization.Response, error)
	// WiFi
	GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error)
	DeleteWiFiSetting(instanceId string) error
	EnableWiFi(enableSync, enableWiFiSharing bool) error
	AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (wifiportconfiguration.Response, error)
	// Wired
	GetEthernetSettings() ([]ethernetport.SettingsResponse, error)
	PutEthernetSettings(ethernetPortSettings ethernetport.SettingsRequest, instanceId string) (ethernetport.Response, error)
	GetIPSIEEE8021xSettings() (response ieee8021x.Response, err error)
	PutIPSIEEE8021xSettings(ieee8021xSettings ieee8021x.IEEE8021xSettingsRequest) (response ieee8021x.Response, err error)
	SetIPSIEEE8021xCertificates(serverCertificateIssuer, clientCertificate string) (response ieee8021x.Response, err error)
	// TLS
	CreateTLSCredentialContext(certHandle string) (response tls.Response, err error)
	PutTLSCredentialContext(certHandle string) (response tls.Response, err error)
	EnumerateTLSSettingData() (response tls.Response, err error)
	PullTLSSettingData(enumerationContext string) (response tls.Response, err error)
	PUTTLSSettings(instanceID string, tlsSettingData tls.SettingDataRequest) (response tls.Response, err error)
	// CIRA
	GetMPSSAP() (response []managementpresence.ManagementRemoteResponse, err error)
	RemoveMPSSAP(name string) (err error)
	GetRemoteAccessPolicies() (response []remoteaccess.RemoteAccessPolicyAppliesToMPSResponse, err error)
	AddMPS(password, mpsAddress string, port int) (response remoteaccess.AddMpServerResponse, err error)
	AddRemoteAccessPolicyRule(remoteAccessTrigger remoteaccess.Trigger, selectorValue string) (response remoteaccess.AddRemoteAccessPolicyRuleResponse, err error)
	PutRemoteAccessPolicyAppliesToMPS(policy remoteaccess.RemoteAccessPolicyAppliesToMPSResponse) (response remoteaccess.Body, err error)
	RemoveRemoteAccessPolicyRules() error
	RequestStateChangeCIRA() (response userinitiatedconnection.RequestStateChange_OUTPUT, err error)
	GetEnvironmentDetectionSettings() (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error)
	PutEnvironmentDetectionSettings(environmentDetectionSettingData environmentdetection.EnvironmentDetectionSettingDataRequest) (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error)

	CommitChanges() (response setupandconfiguration.Response, err error)
	GeneratePKCS10RequestEx(keyPair, nullSignedCertificateRequest string, signingAlgorithm publickey.SigningAlgorithm) (response publickey.Response, err error)

	RequestRedirectionStateChange(requestedState redirection.RequestedState) (response redirection.Response, err error)
	RequestKVMStateChange(requestedState kvm.KVMRedirectionSAPRequestStateChangeInput) (response kvm.Response, err error)
	PutRedirectionState(requestedState *redirection.RedirectionRequest) (response redirection.Response, err error)
	GetRedirectionService() (response redirection.Response, err error)
	GetIpsOptInService() (response optin.Response, err error)
	PutIpsOptInService(request optin.OptInServiceRequest) (response optin.Response, err error)
}
