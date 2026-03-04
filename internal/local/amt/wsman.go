/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/base64"
	"net"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
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
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/hostbasedsetup"
	ipshttp "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/http"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/ips/optin"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/sirupsen/logrus"
)

// WSMANer interface is now in the interfaces package
type WSMANer = interfaces.WSMANer

type GoWSMANMessages struct {
	wsmanMessages wsman.Messages
	target        string
}

func NewGoWSMANMessages(lmsAddress string) *GoWSMANMessages {
	return &GoWSMANMessages{
		target: lmsAddress,
	}
}

func logWSMANOperation(operation string, err error) {
	if err != nil {
		logrus.Errorf("%s failed: %v", operation, err)

		return
	}

	logrus.Infof("%s successful", operation)
}

func (g *GoWSMANMessages) SetupWsmanClient(username, password string, useTLS, logAMTMessages bool, tlsConfig *cryptotls.Config) error {
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dialer := &cryptotls.Dialer{
			Config: tlsConfig,
		}

		conn, err := dialer.DialContext(ctx, "tcp", utils.LMSAddress+":"+utils.LMSTLSPort)
		if err != nil {
			logrus.Info("Failed to connect to LMS.  We're probably going to fail now. Sorry!")
			logrus.Error(err)
		} else {
			logrus.Info("Successfully connected to LMS.")

			if tlsConn, ok := conn.(*cryptotls.Conn); ok {
				state := tlsConn.ConnectionState()
				cert := state.PeerCertificates[0]
				logrus.Trace("Server certificate: ", cert)
			}

			defer conn.Close()
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dialer := &net.Dialer{}

		con, err := dialer.DialContext(ctx, "tcp4", utils.LMSAddress+":"+utils.LMSPort)
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
	response, err := g.wsmanMessages.AMT.GeneralSettings.Get()
	logWSMANOperation("AMT_GeneralSettings_Get", err)

	return response, err
}

func (g *GoWSMANMessages) PutGeneralSettings(request general.GeneralSettingsRequest) (general.Response, error) {
	response, err := g.wsmanMessages.AMT.GeneralSettings.Put(request)
	logWSMANOperation("AMT_GeneralSettings_Put", err)

	return response, err
}

func (g *GoWSMANMessages) HostBasedSetupService(digestRealm, password string) (hostbasedsetup.Response, error) {
	response, err := g.wsmanMessages.IPS.HostBasedSetupService.Setup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password)
	logWSMANOperation("IPS_HostBasedSetupService_Setup", err)

	return response, err
}

func (g *GoWSMANMessages) GetHostBasedSetupService() (hostbasedsetup.Response, error) {
	response, err := g.wsmanMessages.IPS.HostBasedSetupService.Get()
	logWSMANOperation("IPS_HostBasedSetupService_Get", err)

	return response, err
}

func (g *GoWSMANMessages) AddNextCertInChain(cert string, isLeaf, isRoot bool) (hostbasedsetup.Response, error) {
	response, err := g.wsmanMessages.IPS.HostBasedSetupService.AddNextCertInChain(cert, isLeaf, isRoot)
	logWSMANOperation("IPS_HostBasedSetupService_AddNextCertInChain", err)

	return response, err
}

func (g *GoWSMANMessages) HostBasedSetupServiceAdmin(password, digestRealm string, nonce []byte, signature string, isUpgrade bool) (hostbasedsetup.Response, error) {
	if isUpgrade {
		response, err := g.wsmanMessages.IPS.HostBasedSetupService.UpgradeClientToAdmin(base64.StdEncoding.EncodeToString(nonce), hostbasedsetup.SigningAlgorithmRSASHA2256, signature)
		logWSMANOperation("IPS_HostBasedSetupService_UpgradeClientToAdmin", err)

		return response, err
	}

	response, err := g.wsmanMessages.IPS.HostBasedSetupService.AdminSetup(hostbasedsetup.AdminPassEncryptionTypeHTTPDigestMD5A1, digestRealm, password, base64.StdEncoding.EncodeToString(nonce), hostbasedsetup.SigningAlgorithmRSASHA2256, signature)
	logWSMANOperation("IPS_HostBasedSetupService_AdminSetup", err)

	return response, err
}

func (g *GoWSMANMessages) PartialUnprovision() (setupandconfiguration.Response, error) {
	response, err := g.wsmanMessages.AMT.SetupAndConfigurationService.PartialUnprovision()
	logWSMANOperation("AMT_SetupAndConfigurationService_PartialUnprovision", err)

	return response, err
}

func (g *GoWSMANMessages) Unprovision(int) (setupandconfiguration.Response, error) {
	response, err := g.wsmanMessages.AMT.SetupAndConfigurationService.Unprovision(1)
	logWSMANOperation("AMT_SetupAndConfigurationService_Unprovision", err)

	return response, err
}

func (g *GoWSMANMessages) SetupMEBX(password string) (response setupandconfiguration.Response, err error) {
	response, err = g.wsmanMessages.AMT.SetupAndConfigurationService.SetMEBXPassword(password)
	logWSMANOperation("AMT_SetupAndConfigurationService_SetMEBXPassword", err)

	return response, err
}

func (g *GoWSMANMessages) GetSetupAndConfigurationService() (setupandconfiguration.Response, error) {
	response, err := g.wsmanMessages.AMT.SetupAndConfigurationService.Get()
	logWSMANOperation("AMT_SetupAndConfigurationService_Get", err)

	return response, err
}

func (g *GoWSMANMessages) GetPublicKeyCerts() ([]publickey.RefinedPublicKeyCertificateResponse, error) {
	response, err := g.wsmanMessages.AMT.PublicKeyCertificate.Enumerate()
	logWSMANOperation("AMT_PublicKeyCertificate_Enumerate", err)

	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.AMT.PublicKeyCertificate.Pull(response.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("AMT_PublicKeyCertificate_Pull", err)

	if err != nil {
		return nil, err
	}

	return response.Body.RefinedPullResponse.PublicKeyCertificateItems, nil
}

func (g *GoWSMANMessages) GenerateKeyPair(keyAlgorithm publickey.KeyAlgorithm, keyLength publickey.KeyLength) (response publickey.Response, err error) {
	response, err = g.wsmanMessages.AMT.PublicKeyManagementService.GenerateKeyPair(keyAlgorithm, keyLength)
	logWSMANOperation("AMT_PublicKeyManagementService_GenerateKeyPair", err)

	return response, err
}

func (g *GoWSMANMessages) UpdateAMTPassword(digestPassword string) (authorization.Response, error) {
	response, err := g.wsmanMessages.AMT.AuthorizationService.SetAdminAclEntryEx(utils.AMTUserName, digestPassword)
	logWSMANOperation("AMT_AuthorizationService_SetAdminAclEntryEx", err)

	return response, err
}

func (g *GoWSMANMessages) CreateTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	response, err = g.wsmanMessages.AMT.TLSCredentialContext.Create(certHandle)
	logWSMANOperation("AMT_TLSCredentialContext_Create", err)

	return response, err
}

func (g *GoWSMANMessages) PutTLSCredentialContext(certHandle string) (response tls.Response, err error) {
	response, err = g.wsmanMessages.AMT.TLSCredentialContext.Put(certHandle)
	logWSMANOperation("AMT_TLSCredentialContext_Put", err)

	return response, err
}

// GetPublicPrivateKeyPairs
// NOTE: RSA Key encoded as DES PKCS#1. The Exponent (E) is 65537 (0x010001).
// When this structure is used as an output parameter (GET or PULL method),
// only the public section of the key is exported.
func (g *GoWSMANMessages) GetPublicPrivateKeyPairs() ([]publicprivate.RefinedPublicPrivateKeyPair, error) {
	response, err := g.wsmanMessages.AMT.PublicPrivateKeyPair.Enumerate()
	logWSMANOperation("AMT_PublicPrivateKeyPair_Enumerate", err)

	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.AMT.PublicPrivateKeyPair.Pull(response.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("AMT_PublicPrivateKeyPair_Pull", err)

	if err != nil {
		return nil, err
	}

	return response.Body.RefinedPullResponse.PublicPrivateKeyPairItems, nil
}

func (g *GoWSMANMessages) GetWiFiSettings() ([]wifi.WiFiEndpointSettingsResponse, error) {
	response, err := g.wsmanMessages.CIM.WiFiEndpointSettings.Enumerate()
	logWSMANOperation("CIM_WiFiEndpointSettings_Enumerate", err)

	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.CIM.WiFiEndpointSettings.Pull(response.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("CIM_WiFiEndpointSettings_Pull", err)

	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.EndpointSettingsItems, nil
}

func (g *GoWSMANMessages) GetEthernetSettings() ([]ethernetport.SettingsResponse, error) {
	response, err := g.wsmanMessages.AMT.EthernetPortSettings.Enumerate()
	logWSMANOperation("AMT_EthernetPortSettings_Enumerate", err)

	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.AMT.EthernetPortSettings.Pull(response.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("AMT_EthernetPortSettings_Pull", err)

	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.EthernetPortItems, nil
}

func (g *GoWSMANMessages) PutEthernetSettings(ethernetPortSettings ethernetport.SettingsRequest, instanceId string) (ethernetport.Response, error) {
	response, err := g.wsmanMessages.AMT.EthernetPortSettings.Put(instanceId, ethernetPortSettings)
	logWSMANOperation("AMT_EthernetPortSettings_Put", err)

	return response, err
}

func (g *GoWSMANMessages) DeletePublicPrivateKeyPair(instanceId string) error {
	_, err := g.wsmanMessages.AMT.PublicPrivateKeyPair.Delete(instanceId)
	logWSMANOperation("AMT_PublicPrivateKeyPair_Delete", err)

	return err
}

func (g *GoWSMANMessages) DeletePublicCert(instanceId string) error {
	_, err := g.wsmanMessages.AMT.PublicKeyCertificate.Delete(instanceId)
	logWSMANOperation("AMT_PublicKeyCertificate_Delete", err)

	return err
}

func (g *GoWSMANMessages) GetCredentialRelationships() (credential.Items, error) {
	response, err := g.wsmanMessages.CIM.CredentialContext.Enumerate()
	logWSMANOperation("CIM_CredentialContext_Enumerate", err)

	if err != nil {
		return credential.Items{}, err
	}

	response, err = g.wsmanMessages.CIM.CredentialContext.Pull(response.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("CIM_CredentialContext_Pull", err)

	if err != nil {
		return credential.Items{}, err
	}

	return response.Body.PullResponse.Items, nil
}

func (g *GoWSMANMessages) GetConcreteDependencies() ([]concrete.ConcreteDependency, error) {
	response, err := g.wsmanMessages.CIM.ConcreteDependency.Enumerate()
	logWSMANOperation("CIM_ConcreteDependency_Enumerate", err)

	if err != nil {
		return nil, err
	}

	response, err = g.wsmanMessages.CIM.ConcreteDependency.Pull(response.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("CIM_ConcreteDependency_Pull", err)

	if err != nil {
		return nil, err
	}

	return response.Body.PullResponse.Items, nil
}

func (g *GoWSMANMessages) DeleteWiFiSetting(instanceID string) error {
	_, err := g.wsmanMessages.CIM.WiFiEndpointSettings.Delete(instanceID)
	logWSMANOperation("CIM_WiFiEndpointSettings_Delete", err)

	return err
}

func (g *GoWSMANMessages) AddTrustedRootCert(caCert string) (handle string, err error) {
	response, err := g.wsmanMessages.AMT.PublicKeyManagementService.AddTrustedRootCertificate(caCert)
	logWSMANOperation("AMT_PublicKeyManagementService_AddTrustedRootCertificate", err)

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
	logWSMANOperation("AMT_PublicKeyManagementService_AddCertificate", err)

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
	logWSMANOperation("AMT_PublicKeyManagementService_AddKey", err)

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
	logWSMANOperation("AMT_PublicKeyManagementService_Delete", err)

	return err
}

func (g *GoWSMANMessages) EnableWiFi(enableSync, uefiWiFiSync bool) error {
	response, err := g.wsmanMessages.AMT.WiFiPortConfigurationService.Get()
	logWSMANOperation("AMT_WiFiPortConfigurationService_Get", err)

	if err != nil {
		return err
	}

	bootCapabilities, err := g.wsmanMessages.AMT.BootCapabilities.Get()
	logWSMANOperation("AMT_BootCapabilities_Get", err)

	if err != nil {
		return err
	}

	uefiWiFiSyncState := false
	if bootCapabilities.Body.BootCapabilitiesGetResponse.UEFIWiFiCoExistenceAndProfileShare && uefiWiFiSync {
		uefiWiFiSyncState = uefiWiFiSync
	}

	// Determine the sync state based on input parameter
	syncState := wifiportconfiguration.LocalSyncDisabled
	if enableSync {
		syncState = wifiportconfiguration.UnrestrictedSync
	}

	// Apply configuration when either local sync state or UEFI profile share differs
	if response.Body.WiFiPortConfigurationService.LocalProfileSynchronizationEnabled != syncState ||
		response.Body.WiFiPortConfigurationService.UEFIWiFiProfileShareEnabled != uefiWiFiSyncState {
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
			UEFIWiFiProfileShareEnabled:        uefiWiFiSyncState,
		}

		_, err := g.wsmanMessages.AMT.WiFiPortConfigurationService.Put(putRequest)
		logWSMANOperation("AMT_WiFiPortConfigurationService_Put", err)

		if err != nil {
			return err
		}
	}

	// always turn wifi on via state change request
	// Enumeration 32769 - WiFi is enabled in S0 + Sx/AC
	_, err = g.wsmanMessages.CIM.WiFiPort.RequestStateChange(32769)
	logWSMANOperation("CIM_WiFiPort_RequestStateChange", err)

	if err != nil {
		return err // utils.WSMANMessageError
	}

	return nil
}

func (g *GoWSMANMessages) AddWiFiSettings(wifiEndpointSettings wifi.WiFiEndpointSettingsRequest, ieee8021xSettings models.IEEE8021xSettings, wifiEndpoint, clientCredential, caCredential string) (response wifiportconfiguration.Response, err error) {
	response, err = g.wsmanMessages.AMT.WiFiPortConfigurationService.AddWiFiSettings(wifiEndpointSettings, ieee8021xSettings, wifiEndpoint, clientCredential, caCredential)
	logWSMANOperation("AMT_WiFiPortConfigurationService_AddWiFiSettings", err)

	return response, err
}

func (g *GoWSMANMessages) PUTTLSSettings(instanceID string, tlsSettingData tls.SettingDataRequest) (response tls.Response, err error) {
	response, err = g.wsmanMessages.AMT.TLSSettingData.Put(instanceID, tlsSettingData)
	logWSMANOperation("AMT_TLSSettingData_Put", err)

	return response, err
}

func (g *GoWSMANMessages) GetLowAccuracyTimeSynch() (response timesynchronization.Response, err error) {
	response, err = g.wsmanMessages.AMT.TimeSynchronizationService.GetLowAccuracyTimeSynch()
	logWSMANOperation("AMT_TimeSynchronizationService_GetLowAccuracyTimeSynch", err)

	return response, err
}

func (g *GoWSMANMessages) SetHighAccuracyTimeSynch(ta0, tm1, tm2 int64) (response timesynchronization.Response, err error) {
	response, err = g.wsmanMessages.AMT.TimeSynchronizationService.SetHighAccuracyTimeSynch(ta0, tm1, tm2)
	logWSMANOperation("AMT_TimeSynchronizationService_SetHighAccuracyTimeSynch", err)

	return response, err
}

func (g *GoWSMANMessages) EnumerateTLSSettingData() (response tls.Response, err error) {
	response, err = g.wsmanMessages.AMT.TLSSettingData.Enumerate()
	logWSMANOperation("AMT_TLSSettingData_Enumerate", err)

	return response, err
}

func (g *GoWSMANMessages) PullTLSSettingData(enumerationContext string) (response tls.Response, err error) {
	response, err = g.wsmanMessages.AMT.TLSSettingData.Pull(enumerationContext)
	logWSMANOperation("AMT_TLSSettingData_Pull", err)

	return response, err
}

func (g *GoWSMANMessages) CommitChanges() (response setupandconfiguration.Response, err error) {
	response, err = g.wsmanMessages.AMT.SetupAndConfigurationService.CommitChanges()
	logWSMANOperation("AMT_SetupAndConfigurationService_CommitChanges", err)

	return response, err
}

func (g *GoWSMANMessages) GeneratePKCS10RequestEx(keyPair, nullSignedCertificateRequest string, signingAlgorithm publickey.SigningAlgorithm) (response publickey.Response, err error) {
	response, err = g.wsmanMessages.AMT.PublicKeyManagementService.GeneratePKCS10RequestEx(keyPair, nullSignedCertificateRequest, signingAlgorithm)
	logWSMANOperation("AMT_PublicKeyManagementService_GeneratePKCS10RequestEx", err)

	return response, err
}

func (g *GoWSMANMessages) GetIPSIEEE8021xSettings() (response ieee8021x.Response, err error) {
	response, err = g.wsmanMessages.IPS.IEEE8021xSettings.Get()
	logWSMANOperation("IPS_IEEE8021xSettings_Get", err)

	return response, err
}

func (g *GoWSMANMessages) PutIPSIEEE8021xSettings(ieee8021xSettings ieee8021x.IEEE8021xSettingsRequest) (response ieee8021x.Response, err error) {
	response, err = g.wsmanMessages.IPS.IEEE8021xSettings.Put(ieee8021xSettings)
	logWSMANOperation("IPS_IEEE8021xSettings_Put", err)

	return response, err
}

func (g *GoWSMANMessages) SetIPSIEEE8021xCertificates(serverCertificateIssuer, clientCertificate string) (response ieee8021x.Response, err error) {
	response, err = g.wsmanMessages.IPS.IEEE8021xSettings.SetCertificates(serverCertificateIssuer, clientCertificate)
	logWSMANOperation("IPS_IEEE8021xSettings_SetCertificates", err)

	return response, err
}

func (g *GoWSMANMessages) RequestRedirectionStateChange(requestedState redirection.RequestedState) (response redirection.Response, err error) {
	response, err = g.wsmanMessages.AMT.RedirectionService.RequestStateChange(requestedState)
	logWSMANOperation("AMT_RedirectionService_RequestStateChange", err)

	return response, err
}

func (g *GoWSMANMessages) RequestKVMStateChange(requestedState kvm.KVMRedirectionSAPRequestStateChangeInput) (response kvm.Response, err error) {
	response, err = g.wsmanMessages.CIM.KVMRedirectionSAP.RequestStateChange(requestedState)
	logWSMANOperation("CIM_KVMRedirectionSAP_RequestStateChange", err)

	return response, err
}

func (g *GoWSMANMessages) PutRedirectionState(requestedState *redirection.RedirectionRequest) (response redirection.Response, err error) {
	response, err = g.wsmanMessages.AMT.RedirectionService.Put(requestedState)
	logWSMANOperation("AMT_RedirectionService_Put", err)

	return response, err
}

func (g *GoWSMANMessages) GetRedirectionService() (response redirection.Response, err error) {
	response, err = g.wsmanMessages.AMT.RedirectionService.Get()
	logWSMANOperation("AMT_RedirectionService_Get", err)

	return response, err
}

func (g *GoWSMANMessages) GetIpsOptInService() (response optin.Response, err error) {
	response, err = g.wsmanMessages.IPS.OptInService.Get()
	logWSMANOperation("IPS_OptInService_Get", err)

	return response, err
}

func (g *GoWSMANMessages) PutIpsOptInService(request optin.OptInServiceRequest) (response optin.Response, err error) {
	response, err = g.wsmanMessages.IPS.OptInService.Put(request)
	logWSMANOperation("IPS_OptInService_Put", err)

	return response, err
}

func (g *GoWSMANMessages) GetMPSSAP() (response []managementpresence.ManagementRemoteResponse, err error) {
	enumResult, err := g.wsmanMessages.AMT.ManagementPresenceRemoteSAP.Enumerate()
	logWSMANOperation("AMT_ManagementPresenceRemoteSAP_Enumerate", err)

	if err != nil {
		return nil, err
	}

	pullResult, err := g.wsmanMessages.AMT.ManagementPresenceRemoteSAP.Pull(enumResult.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("AMT_ManagementPresenceRemoteSAP_Pull", err)

	if err != nil {
		return nil, err
	}

	return pullResult.Body.PullResponse.ManagementRemoteItems, nil
}

func (g *GoWSMANMessages) AddMPS(password, server string, port int) (response remoteaccess.AddMpServerResponse, err error) {
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
	logWSMANOperation("AMT_RemoteAccessService_AddMPS", err)

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
	logWSMANOperation("AMT_RemoteAccessService_AddRemoteAccessPolicyRule", err)

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
	logWSMANOperation("AMT_RemoteAccessPolicyAppliesToMPS_Put", err)

	if err != nil {
		return result.Body, err
	}

	return result.Body, nil
}

func (g *GoWSMANMessages) RemoveMPSSAP(name string) (err error) {
	_, err = g.wsmanMessages.AMT.ManagementPresenceRemoteSAP.Delete(name)
	logWSMANOperation("AMT_ManagementPresenceRemoteSAP_Delete", err)

	if err != nil {
		return err
	}

	return nil
}

func (g *GoWSMANMessages) GetRemoteAccessPolicies() (response []remoteaccess.RemoteAccessPolicyAppliesToMPSResponse, err error) {
	enumResult, err := g.wsmanMessages.AMT.RemoteAccessPolicyAppliesToMPS.Enumerate()
	logWSMANOperation("AMT_RemoteAccessPolicyAppliesToMPS_Enumerate", err)

	if err != nil {
		return nil, err
	}

	pullResult, err := g.wsmanMessages.AMT.RemoteAccessPolicyAppliesToMPS.Pull(enumResult.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("AMT_RemoteAccessPolicyAppliesToMPS_Pull", err)

	if err != nil {
		return nil, err
	}

	return pullResult.Body.PullResponse.PolicyAppliesItems, nil
}

func (g *GoWSMANMessages) RemoveRemoteAccessPolicyRules() error {
	_, err := g.wsmanMessages.AMT.RemoteAccessPolicyRule.Delete("User Initiated")
	logWSMANOperation("AMT_RemoteAccessPolicyRule_Delete_UserInitiated", err)

	if err != nil && !strings.Contains(err.Error(), "DestinationUnreachable") {
		return err
	}

	_, err = g.wsmanMessages.AMT.RemoteAccessPolicyRule.Delete("Alert")
	logWSMANOperation("AMT_RemoteAccessPolicyRule_Delete_Alert", err)

	if err != nil && !strings.Contains(err.Error(), "DestinationUnreachable") {
		return err
	}

	_, err = g.wsmanMessages.AMT.RemoteAccessPolicyRule.Delete("Periodic")
	logWSMANOperation("AMT_RemoteAccessPolicyRule_Delete_Periodic", err)

	if err != nil && !strings.Contains(err.Error(), "DestinationUnreachable") {
		return err
	}

	return nil
}

func (g *GoWSMANMessages) RequestStateChangeCIRA() (response userinitiatedconnection.RequestStateChange_OUTPUT, err error) {
	result, err := g.wsmanMessages.AMT.UserInitiatedConnectionService.RequestStateChange(userinitiatedconnection.BIOSandOSInterfacesEnabled)
	logWSMANOperation("AMT_UserInitiatedConnectionService_RequestStateChange", err)

	if err != nil {
		return response, err
	}

	return result.Body.RequestStateChange_OUTPUT, nil
}

func (g *GoWSMANMessages) GetEnvironmentDetectionSettings() (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error) {
	result, err := g.wsmanMessages.AMT.EnvironmentDetectionSettingData.Get()
	logWSMANOperation("AMT_EnvironmentDetectionSettingData_Get", err)

	if err != nil {
		return response, err
	}

	return result.Body.GetAndPutResponse, nil
}

func (g *GoWSMANMessages) PutEnvironmentDetectionSettings(request environmentdetection.EnvironmentDetectionSettingDataRequest) (response environmentdetection.EnvironmentDetectionSettingDataResponse, err error) {
	result, err := g.wsmanMessages.AMT.EnvironmentDetectionSettingData.Put(request)
	logWSMANOperation("AMT_EnvironmentDetectionSettingData_Put", err)

	if err != nil {
		return response, err
	}

	return result.Body.GetAndPutResponse, nil
}

// GetHTTPProxy retrieves the HTTP Proxy settings via enumerate/pull
func (g *GoWSMANMessages) GetHTTPProxy() (response ipshttp.Response, err error) {
	enumResult, err := g.wsmanMessages.IPS.HTTPProxyService.Enumerate()
	logWSMANOperation("IPS_HTTPProxyService_Enumerate", err)

	if err != nil {
		return response, err
	}

	pullResult, err := g.wsmanMessages.IPS.HTTPProxyService.Pull(enumResult.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("IPS_HTTPProxyService_Pull", err)

	if err != nil {
		return response, err
	}

	return pullResult, nil
}

// GetHTTPProxyAccessPoints retrieves all configured proxy access points
func (g *GoWSMANMessages) GetHTTPProxyAccessPoints() (response []ipshttp.HTTPProxyAccessPointItem, err error) {
	enumResult, err := g.wsmanMessages.IPS.HTTPProxyAccessPointService.Enumerate()
	logWSMANOperation("IPS_HTTPProxyAccessPointService_Enumerate", err)

	if err != nil {
		return nil, err
	}

	pullResult, err := g.wsmanMessages.IPS.HTTPProxyAccessPointService.Pull(enumResult.Body.EnumerateResponse.EnumerationContext)
	logWSMANOperation("IPS_HTTPProxyAccessPointService_Pull", err)

	if err != nil {
		return nil, err
	}

	return pullResult.Body.PullResponse.Items, nil
}

// DeleteHTTPProxyAccessPoint deletes an IPS HTTP Proxy Access Point by name
func (g *GoWSMANMessages) DeleteHTTPProxyAccessPoint(name string) (response ipshttp.ProxyAccessPointResponse, err error) {
	response, err = g.wsmanMessages.IPS.HTTPProxyAccessPointService.Delete(name)
	logWSMANOperation("IPS_HTTPProxyAccessPointService_Delete", err)

	return response, err
}

// AddHTTPProxyAccessPoint adds an IPS HTTP Proxy Access Point via IPS_HTTPProxyService
func (g *GoWSMANMessages) AddHTTPProxyAccessPoint(accessInfo string, infoFormat, port int, networkDnsSuffix string) (response ipshttp.Response, err error) {
	// Convert infoFormat int to the library enum
	var fmtEnum ipshttp.InfoFormat

	switch infoFormat {
	case int(ipshttp.InfoFormatIPv4):
		fmtEnum = ipshttp.InfoFormatIPv4
	case int(ipshttp.InfoFormatIPv6):
		fmtEnum = ipshttp.InfoFormatIPv6
	default:
		fmtEnum = ipshttp.InfoFormatFQDN
	}

	response, err = g.wsmanMessages.IPS.HTTPProxyService.AddProxyAccessPoint(accessInfo, fmtEnum, port, networkDnsSuffix)
	logWSMANOperation("IPS_HTTPProxyService_AddProxyAccessPoint", err)

	return response, err
}
