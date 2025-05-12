/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	cryptotls "crypto/tls"
	"encoding/base64"
	"net"
	"strings"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/authorization"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/general"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/managementpresence"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/redirection"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/remoteaccess"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/timesynchronization"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/userinitiatedconnection"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/wifiportconfiguration"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/concrete"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/credential"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/kvm"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/models"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	"github.com/sirupsen/logrus"
)

type WSMANer interface {
	SetupWsmanClient(username string, password string, useTLS bool, logAMTMessages bool, tlsConfig *cryptotls.Config) error
	Unprovision(int) (setupandconfiguration.Response, error)
	PartialUnprovision() (setupandconfiguration.Response, error)
	GetGeneralSettings() (general.Response, error)
	HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error)
	GetHostBasedSetupService() (hostbasedsetup.Response, error)
	AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error)
	HostBasedSetupServiceAdmin(password string, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error)
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
	SetHighAccuracyTimeSynch(ta0 int64, tm1 int64, tm2 int64) (response timesynchronization.Response, err error)
	GenerateKeyPair(keyAlgorithm publickey.KeyAlgorithm, keyLength publickey.KeyLength) (response publickey.Response, err error)
	UpdateAMTPassword(passwordBase64 string) (authorization.Response, error)
	// WiFi
	GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error)
	DeleteWiFiSetting(instanceId string) error
	EnableWiFi(enableSync bool) error
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
	AddMPS(password string, mpsAddress string, port int) (response remoteaccess.AddMpServerResponse, err error)
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
	PutRedirectionState(requestedState redirection.RedirectionRequest) (response redirection.Response, err error)
	GetRedirectionService() (response redirection.Response, err error)
	GetIpsOptInService() (response optin.Response, err error)
	PutIpsOptInService(request optin.OptInServiceRequest) (response optin.Response, err error)
}

type GoWSMANMessages struct {
	wsmanMessages wsman.Messages
	target        string
}

func NewGoWSMANMessages(lmsAddress string) *GoWSMANMessages {
	return &GoWSMANMessages{
		target: lmsAddress,
	}
}

func (g *GoWSMANMessages) SetupWsmanClient(username string, password string, useTLS bool, logAMTMessages bool, tlsConfig *cryptotls.Config) error {
	clientParams := client.Parameters{
		Target:         g.target,
		Username:       username,
		Password:       password,
		UseDigest:      true,
		UseTLS:         useTLS,
		TlsConfig:      tlsConfig,
		LogAMTMessages: logAMTMessages,
	}

	if clientParams.UseTLS {
		clientParams.SelfSignedAllowed = tlsConfig.InsecureSkipVerify

		conn, err := cryptotls.Dial("tcp", utils.LMSAddress+":"+utils.LMSTLSPort, tlsConfig)
		if err != nil {
			logrus.Info("Failed to connect to LMS.  We're probably going to fail now. Sorry!")
			logrus.Error(err)
		} else {
			logrus.Info("Successfully connected to LMS.")

			state := conn.ConnectionState()
			cert := state.PeerCertificates[0]
			logrus.Trace("Server certificate: ", cert)

			defer conn.Close()
		}
	} else {
		con, err := net.Dial("tcp4", utils.LMSAddress+":"+utils.LMSPort)
		if err != nil {
			logrus.Info("Failed to connect to LMS, using local transport instead.")

			clientParams.Transport = NewLocalTransport()
		} else {
			logrus.Info("Successfully connected to LMS.")
			con.Close()
		}
	}

	g.wsmanMessages = wsman.NewMessages(clientParams)

	return nil
}

func (g *GoWSMANMessages) GetGeneralSettings() (general.Response, error) {
	return g.wsmanMessages.AMT.GeneralSettings.Get()
}

func (g *GoWSMANMessages) HostBasedSetupService(digestRealm string, password string) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.Setup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password)
}

func (g *GoWSMANMessages) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.Get()
}

func (g *GoWSMANMessages) AddNextCertInChain(cert string, isLeaf bool, isRoot bool) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.AddNextCertInChain(cert, isLeaf, isRoot)
}

func (g *GoWSMANMessages) HostBasedSetupServiceAdmin(password, digestRealm string, nonce []byte, signature string) (hostbasedsetup.Response, error) {
	return g.wsmanMessages.IPS.HostBasedSetupService.AdminSetup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password, base64.StdEncoding.EncodeToString(nonce), hostbasedsetup.SigningAlgorithmRSASHA2256, signature)
}
func (g *GoWSMANMessages) PartialUnprovision() (setupandconfiguration.Response, error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.PartialUnprovision()
}

func (g *GoWSMANMessages) Unprovision(int) (setupandconfiguration.Response, error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.Unprovision(1)
}

func (g *GoWSMANMessages) SetupMEBX(password string) (response setupandconfiguration.Response, err error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.SetMEBXPassword(password)
}

func (g *GoWSMANMessages) GetSetupAndConfigurationService() (setupandconfiguration.Response, error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.Get()
}

func (g *GoWSMANMessages) GetPublicKeyCerts() ([]publickey.RefinedPublicKeyCertificateResponse, error) {
	response, err := g.wsmanMessages.AMT.PublicKeyCertificate.Enumerate()
	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.AMT.PublicKeyCertificate.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return response.Body.RefinedPullResponse.PublicKeyCertificateItems, nil
}

func (g *GoWSMANMessages) GenerateKeyPair(keyAlgorithm publickey.KeyAlgorithm, keyLength publickey.KeyLength) (response publickey.Response, err error) {
	return g.wsmanMessages.AMT.PublicKeyManagementService.GenerateKeyPair(keyAlgorithm, keyLength)
}

func (g *GoWSMANMessages) UpdateAMTPassword(digestPassword string) (authorization.Response, error) {
	return g.wsmanMessages.AMT.AuthorizationService.SetAdminAclEntryEx(utils.AMTUserName, digestPassword)
}

func (g *GoWSMANMessages) CreateTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	return g.wsmanMessages.AMT.TLSCredentialContext.Create(certHandle)
}

func (g *GoWSMANMessages) PutTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	return g.wsmanMessages.AMT.TLSCredentialContext.Put(certHandle)
}

// GetPublicPrivateKeyPairs
// NOTE: RSA Key encoded as DES PKCS#1. The Exponent (E) is 65537 (0x010001).
// When this structure is used as an output parameter (GET or PULL method),
// only the public section of the key is exported.
func (g *GoWSMANMessages) GetPublicPrivateKeyPairs() ([]publicprivate.RefinedPublicPrivateKeyPair, error) {
	response, err := g.wsmanMessages.AMT.PublicPrivateKeyPair.Enumerate()
	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.AMT.PublicPrivateKeyPair.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return response.Body.RefinedPullResponse.PublicPrivateKeyPairItems, nil
}
func (g *GoWSMANMessages) GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error) {
	response, err := g.wsmanMessages.CIM.WiFiEndpointSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.CIM.WiFiEndpointSettings.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.EndpointSettingsItems, nil
}
func (g *GoWSMANMessages) GetEthernetSettings() ([]ethernetport.SettingsResponse, error) {
	response, err := g.wsmanMessages.AMT.EthernetPortSettings.Enumerate()
	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.AMT.EthernetPortSettings.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.EthernetPortItems, nil
}
func (g *GoWSMANMessages) PutEthernetSettings(ethernetPortSettings ethernetport.SettingsRequest, instanceId string) (ethernetport.Response, error) {
	return g.wsmanMessages.AMT.EthernetPortSettings.Put(instanceId, ethernetPortSettings)
}
func (g *GoWSMANMessages) DeletePublicPrivateKeyPair(instanceId string) error {
	_, err := g.wsmanMessages.AMT.PublicPrivateKeyPair.Delete(instanceId)

	return err
}
func (g *GoWSMANMessages) DeletePublicCert(instanceId string) error {
	_, err := g.wsmanMessages.AMT.PublicKeyCertificate.Delete(instanceId)

	return err
}
func (g *GoWSMANMessages) GetCredentialRelationships() (credential.Items, error) {
	response, err := g.wsmanMessages.CIM.CredentialContext.Enumerate()
	if err != nil {
		return credential.Items{}, err
	}

	response, err = g.wsmanMessages.CIM.CredentialContext.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return credential.Items{}, err
	}

	return response.Body.PullResponse.Items, nil
}
func (g *GoWSMANMessages) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	response, err := g.wsmanMessages.CIM.ConcreteDependency.Enumerate()
	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.CIM.ConcreteDependency.Pull(response.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.Items, nil
}
func (g *GoWSMANMessages) DeleteWiFiSetting(instanceID string) error {
	_, err := g.wsmanMessages.CIM.WiFiEndpointSettings.Delete(instanceID)

	return err
}
func (g *GoWSMANMessages) AddTrustedRootCert(caCert string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddTrustedRootCertificate(caCert)
	if err != nil {
		return "", err
	}

	if len(response.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors) > 0 {
		handle = response.Body.AddTrustedRootCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors[0].Text
	}

	return handle, nil
}
func (g *GoWSMANMessages) AddClientCert(clientCert string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddCertificate(clientCert)
	if err != nil {
		return "", err
	}

	if len(response.Body.AddCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors) > 0 {
		handle = response.Body.AddCertificate_OUTPUT.CreatedCertificate.ReferenceParameters.SelectorSet.Selectors[0].Text
	}

	return handle, nil
}
func (g *GoWSMANMessages) AddPrivateKey(privateKey string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddKey(privateKey)
	if err != nil && response.Body.AddKey_OUTPUT.ReturnValue == 2058 {
		return "", utils.DuplicateKey
	} else if err != nil {
		return "", err
	}

	if len(response.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selectors) > 0 {
		handle = response.Body.AddKey_OUTPUT.CreatedKey.ReferenceParameters.SelectorSet.Selectors[0].Text
	}

	return handle, nil
}

func (g *GoWSMANMessages) DeleteKeyPair(instanceID string) error {
	_, err := g.wsmanMessages.AMT.PublicKeyManagementService.Delete(instanceID)

	return err
}
func (g *GoWSMANMessages) EnableWiFi(enableSync bool) error {
	response, err := g.wsmanMessages.AMT.WiFiPortConfigurationService.Get()
	if err != nil {
		return err
	}

	// Determine the sync state based on input parameter
	syncState := wifiportconfiguration.LocalSyncDisabled
	if enableSync {
		syncState = wifiportconfiguration.UnrestrictedSync
	}

	// if local sync not enable, enable it
	if response.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled != syncState {
		putRequest := wifiportconfiguration.WiFiPortConfigurationServiceRequest{
			RequestedState:                     response.Body.WiFiPortConfigurationService.RequestedState,
			EnabledState:                       response.Body.WiFiPortConfigurationService.EnabledState,
			HealthState:                        response.Body.WiFiPortConfigurationService.HealthState,
			ElementName:                        response.Body.WiFiPortConfigurationService.ElementName,
			SystemCreationClassName:            response.Body.WiFiPortConfigurationService.SystemCreationClassName,
			SystemName:                         response.Body.WiFiPortConfigurationService.SystemName,
			CreationClassName:                  response.Body.WiFiPortConfigurationService.CreationClassName,
			Name:                               response.Body.WiFiPortConfigurationService.Name,
			LocalProfileSynchronizationEnabled: syncState,
			LastConnectedSsidUnderMeControl:    response.Body.WiFiPortConfigurationService.LastConnectedSsidUnderMeControl,
			NoHostCsmeSoftwarePolicy:           response.Body.WiFiPortConfigurationService.NoHostCsmeSoftwarePolicy,
			UEFIWiFiProfileShareEnabled:        response.Body.WiFiPortConfigurationService.UEFIWiFiProfileShareEnabled,
		}

		_, err := g.wsmanMessages.AMT.WiFiPortConfigurationService.Put(putRequest)
		if err != nil {
			return err
		}
	}

	// always turn wifi on via state change request
	// Enumeration 32769 - WiFi is enabled in S0 + Sx/AC
	_, err = g.wsmanMessages.CIM.WiFiPort.RequestStateChange(32769)
	if err != nil {
		return err // utils.WSMANMessageError
	}

	return nil
}
func (g *GoWSMANMessages) AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (response wifiportconfiguration.Response, err error) {
	return g.wsmanMessages.AMT.WiFiPortConfigurationService.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, wifiEndpoint, clientCredential, caCredential)
}
func (g *GoWSMANMessages) PUTTLSSettings(instanceID string, tlsSettingData tls.SettingDataRequest) (response tls.Response, err error) {
	return g.wsmanMessages.AMT.TLSSettingData.Put(instanceID, tlsSettingData)
}
func (g *GoWSMANMessages) GetLowAccuracyTimeSynch() (response timesynchronization.Response, err error) {
	return g.wsmanMessages.AMT.TimeSynchronizationService.GetLowAccuracyTimeSynch()
}
func (g *GoWSMANMessages) SetHighAccuracyTimeSynch(ta0 int64, tm1 int64, tm2 int64) (response timesynchronization.Response, err error) {
	return g.wsmanMessages.AMT.TimeSynchronizationService.SetHighAccuracyTimeSynch(ta0, tm1, tm2)
}
func (g *GoWSMANMessages) EnumerateTLSSettingData() (response tls.Response, err error) {
	return g.wsmanMessages.AMT.TLSSettingData.Enumerate()
}
func (g *GoWSMANMessages) PullTLSSettingData(enumerationContext string) (response tls.Response, err error) {
	return g.wsmanMessages.AMT.TLSSettingData.Pull(enumerationContext)
}

func (g *GoWSMANMessages) CommitChanges() (response setupandconfiguration.Response, err error) {
	return g.wsmanMessages.AMT.SetupAndConfigurationService.CommitChanges()
}

func (g *GoWSMANMessages) GeneratePKCS10RequestEx(keyPair, nullSignedCertificateRequest string, signingAlgorithm publickey.SigningAlgorithm) (response publickey.Response, err error) {
	return g.wsmanMessages.AMT.PublicKeyManagementService.GeneratePKCS10RequestEx(keyPair, nullSignedCertificateRequest, signingAlgorithm)
}

func (g *GoWSMANMessages) GetIPSIEEE8021xSettings() (response ieee8021x.Response, err error) {
	return g.wsmanMessages.IPS.IEEE8021xSettings.Get()
}

func (g *GoWSMANMessages) PutIPSIEEE8021xSettings(ieee8021xSettings ieee8021x.IEEE8021xSettingsRequest) (response ieee8021x.Response, err error) {
	return g.wsmanMessages.IPS.IEEE8021xSettings.Put(ieee8021xSettings)
}

func (g *GoWSMANMessages) SetIPSIEEE8021xCertificates(serverCertificateIssuer, clientCertificate string) (response ieee8021x.Response, err error) {
	return g.wsmanMessages.IPS.IEEE8021xSettings.SetCertificates(serverCertificateIssuer, clientCertificate)
}

func (g *GoWSMANMessages) RequestRedirectionStateChange(requestedState redirection.RequestedState) (response redirection.Response, err error) {
	return g.wsmanMessages.AMT.RedirectionService.RequestStateChange(requestedState)
}

func (g *GoWSMANMessages) RequestKVMStateChange(requestedState kvm.KVMRedirectionSAPRequestStateChangeInput) (response kvm.Response, err error) {
	return g.wsmanMessages.CIM.KVMRedirectionSAP.RequestStateChange(requestedState)
}

func (g *GoWSMANMessages) PutRedirectionState(requestedState redirection.RedirectionRequest) (response redirection.Response, err error) {
	return g.wsmanMessages.AMT.RedirectionService.Put(requestedState)
}

func (g *GoWSMANMessages) GetRedirectionService() (response redirection.Response, err error) {
	return g.wsmanMessages.AMT.RedirectionService.Get()
}

func (g *GoWSMANMessages) GetIpsOptInService() (response optin.Response, err error) {
	return g.wsmanMessages.IPS.OptInService.Get()
}

func (g *GoWSMANMessages) PutIpsOptInService(request optin.OptInServiceRequest) (response optin.Response, err error) {
	return g.wsmanMessages.IPS.OptInService.Put(request)
}

func (g *GoWSMANMessages) GetMPSSAP() (response []managementpresence.ManagementRemoteResponse, err error) {
	enumResult, err := g.wsmanMessages.AMT.ManagementPresenceRemoteSAP.Enumerate()
	if err != nil {
		return nil, err
	}

	pullResult, err := g.wsmanMessages.AMT.ManagementPresenceRemoteSAP.Pull(enumResult.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return pullResult.Body.PullResponse.ManagementRemoteItems, nil
}

func (g *GoWSMANMessages) AddMPS(password string, server string, port int) (response remoteaccess.AddMpServerResponse, err error) {
	mpsServer := remoteaccess.AddMpServerRequest{
		AccessInfo: server,
		InfoFormat: remoteaccess.IPv4Address,
		Port:       port,
		AuthMethod: remoteaccess.UsernamePasswordAuthentication,
		Username:   "admin",
		Password:   password,
	}

	if mpsServer.InfoFormat == 3 {
		mpsServer.CommonName = server
	}

	result, err := g.wsmanMessages.AMT.RemoteAccessService.AddMPS(mpsServer)

	if err != nil {
		return result.Body.AddMpServerResponse, err
	}

	return result.Body.AddMpServerResponse, nil
}

func (g *GoWSMANMessages) AddRemoteAccessPolicyRule(remoteAccessTrigger remoteaccess.Trigger, selectorValue string) (response remoteaccess.AddRemoteAccessPolicyRuleResponse, err error) {
	policyRule := remoteaccess.RemoteAccessPolicyRuleRequest{
		Trigger:        remoteAccessTrigger,
		TunnelLifeTime: 0,
		ExtendedData:   "AAAAAAAAABk=", // Equals to 25 seconds in base 64 with network order
	}

	if remoteAccessTrigger == remoteaccess.UserInitiated {
		policyRule.TunnelLifeTime = 300
		policyRule.ExtendedData = ""
	}

	result, err := g.wsmanMessages.AMT.RemoteAccessService.AddRemoteAccessPolicyRule(policyRule, selectorValue)
	if err != nil {
		return result.Body.AddRemotePolicyRuleResponse, err
	}

	return result.Body.AddRemotePolicyRuleResponse, nil
}
func (g *GoWSMANMessages) PutRemoteAccessPolicyAppliesToMPS(policy remoteaccess.RemoteAccessPolicyAppliesToMPSResponse) (response remoteaccess.Body, err error) {
	remoteAccessPolicyAppliesToMPS := &remoteaccess.RemoteAccessPolicyAppliesToMPSRequest{
		ManagedElement: remoteaccess.ManagedElement{
			B:       "http://schemas.xmlsoap.org/ws/2004/08/addressing",
			Address: policy.ManagedElement.Address,
			ReferenceParameters: remoteaccess.ReferenceParameters{
				C:           "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
				ResourceURI: policy.ManagedElement.ReferenceParameters.ResourceURI,
			},
		},
		MPSType:       remoteaccess.BothMPS,
		OrderOfAccess: 0,
		PolicySet: remoteaccess.PolicySet{
			Address: policy.PolicySet.Address,
			B:       "http://schemas.xmlsoap.org/ws/2004/08/addressing",
			ReferenceParameters: remoteaccess.ReferenceParameters{
				C:           "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
				ResourceURI: policy.PolicySet.ReferenceParameters.ResourceURI,
			},
		},
	}
	// iterate over the policy set and add the selectors
	for _, policySet := range policy.PolicySet.ReferenceParameters.SelectorSet.Selectors {
		remoteAccessPolicyAppliesToMPS.PolicySet.ReferenceParameters.SelectorSet.Selectors = append(remoteAccessPolicyAppliesToMPS.PolicySet.ReferenceParameters.SelectorSet.Selectors, remoteaccess.Selector{
			Name: policySet.Name,
			Text: policySet.Text,
		})
	}

	result, err := g.wsmanMessages.AMT.RemoteAccessPolicyAppliesToMPS.Put(remoteAccessPolicyAppliesToMPS)
	if err != nil {
		return result.Body, err
	}

	return result.Body, nil
}
func (g *GoWSMANMessages) RemoveMPSSAP(name string) (err error) {
	_, err = g.wsmanMessages.AMT.ManagementPresenceRemoteSAP.Delete(name)
	if err != nil {
		return err
	}

	return nil
}

func (g *GoWSMANMessages) GetRemoteAccessPolicies() (response []remoteaccess.RemoteAccessPolicyAppliesToMPSResponse, err error) {
	enumResult, err := g.wsmanMessages.AMT.RemoteAccessPolicyAppliesToMPS.Enumerate()
	if err != nil {
		return nil, err
	}

	pullResult, err := g.wsmanMessages.AMT.RemoteAccessPolicyAppliesToMPS.Pull(enumResult.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, err
	}

	return pullResult.Body.PullResponse.PolicyAppliesItems, nil
}
func (g *GoWSMANMessages) RemoveRemoteAccessPolicyRules() error {
	_, err := g.wsmanMessages.AMT.RemoteAccessPolicyRule.Delete("User Initiated")
	if err != nil && !strings.Contains(err.Error(), "DestinationUnreachable") {
		return err
	}

	_, err = g.wsmanMessages.AMT.RemoteAccessPolicyRule.Delete("Alert")
	if err != nil && !strings.Contains(err.Error(), "DestinationUnreachable") {
		return err
	}

	_, err = g.wsmanMessages.AMT.RemoteAccessPolicyRule.Delete("Periodic")
	if err != nil && !strings.Contains(err.Error(), "DestinationUnreachable") {
		return err
	}

	return nil
}
func (g *GoWSMANMessages) RequestStateChangeCIRA() (response userinitiatedconnection.RequestStateChange_OUTPUT, err error) {
	result, err := g.wsmanMessages.AMT.UserInitiatedConnectionService.RequestStateChange(userinitiatedconnection.BIOSandOSInterfacesEnabled)
	if err != nil {
		return response, err
	}

	return result.Body.RequestStateChange_OUTPUT, nil
}
func (g *GoWSMANMessages) GetEnvironmentDetectionSettings() (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error) {
	result, err := g.wsmanMessages.AMT.EnvironmentDetectionSettingData.Get()
	if err != nil {
		return response, err
	}

	return result.Body.GetAndPutResponse, nil
}
func (g *GoWSMANMessages) PutEnvironmentDetectionSettings(request environmentdetection.EnvironmentDetectionSettingDataRequest) (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error) {
	result, err := g.wsmanMessages.AMT.EnvironmentDetectionSettingData.Put(request)
	if err != nil {
		return response, err
	}

	return result.Body.GetAndPutResponse, nil
}
