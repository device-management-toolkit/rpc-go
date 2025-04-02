/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"os"
	"strings"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/certs"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"

	log "github.com/sirupsen/logrus"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/tls"
)

const RemoteTLSInstanceId = `Intel(r) AMT 802.3 TLS Settings`
const LocalTLSInstanceId = `Intel(r) AMT LMS TLS Settings`

func (service *ProvisioningService) ConfigureTLS() error {
	var err error
	if service.flags.ConfigTLSInfo.TLSMode != flags.TLSModeDisabled {
		if service.flags.ConfigTLSInfo.EAAddress != "" && service.flags.ConfigTLSInfo.EAUsername != "" && service.flags.ConfigTLSInfo.EAPassword != "" {
			err = service.ValidateURL(service.flags.ConfigTLSInfo.EAAddress)
			if err != nil {
				log.Error("url validation failed: ", err)
				return utils.TLSConfigurationFailed
			}
			err = service.ConfigureTLSWithEA()
		} else {
			err = service.ConfigureTLSWithSelfSignedCert()
		}

		if err != nil {
			return err
		}
	}

	err = service.SynchronizeTime()
	if err != nil {
		return err
	}

	err = service.EnableTLS()
	if err != nil {
		log.Error("Failed to configure TLS")
		return utils.TLSConfigurationFailed
	}

	service.Pause(service.flags.ConfigTLSInfo.DelayInSeconds)
	err = service.PruneCerts()
	if err != nil {
		return err
	}

	log.Info("configuring TLS completed successfully")

	return nil
}

func (service *ProvisioningService) ConfigureTLSWithEA() error {
	log.Info("configuring TLS with Microsoft EA")
	var handles Handles
	var err error
	defer func() {
		if err != nil {
			service.PruneCerts()
		}
	}()
	securitySettings, err := service.GetCertificates()
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	credentials := AuthRequest{
		Username: service.flags.ConfigTLSInfo.EAUsername,
		Password: service.flags.ConfigTLSInfo.EAPassword,
	}
	guid, err := service.amtCommand.GetUUID()

	// Call GetAuthToken
	url := service.flags.ConfigTLSInfo.EAAddress + "/api/authenticate/" + guid
	token, err := service.GetAuthToken(url, credentials)
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return utils.TLSConfigurationFailed
	}
	devName, err := os.Hostname()
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return err
	}
	reqProfile := EAProfile{NodeID: guid, Domain: "", ReqID: "", AuthProtocol: 0, OSName: "win11", DevName: devName, Icon: 1, Ver: ""}

	//Request Profile from Microsoft EA
	url = service.flags.ConfigTLSInfo.EAAddress + "/api/configure/profile/" + guid
	_, err = service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error while requesting EA: %v", err)
		return err
	}

	// Generate KeyPair
	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	// Get DERkey
	derKey, err := service.GetDERKey(handles)
	if derKey == "" {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return utils.TLSConfigurationFailed
	}

	//Request Profile from Microsoft EA
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.keyPairHandle
	url = service.flags.ConfigTLSInfo.EAAddress + "/api/configure/keypair/" + guid
	KeyPairResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error generating 802.1x keypair: %v", err)
		return utils.TLSConfigurationFailed
	}

	response, err := service.interfacedWsmanMessage.GeneratePKCS10RequestEx(KeyPairResponse.Response.KeyInstanceId, KeyPairResponse.Response.CSR, 1)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	url = service.flags.ConfigTLSInfo.EAAddress + "/api/configure/csr/" + guid
	eaResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error signing the certificate: %v", err)
		return utils.TLSConfigurationFailed
	}

	handles.clientCertHandle, err = service.GetClientCertHandle(securitySettings, eaResponse.Response.Certificate)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	err = service.updateTLSCredentialContext(handles)
	if err != nil {
		return utils.TLSConfigurationFailed
	}
	return nil
}

func (service *ProvisioningService) ConfigureTLSWithSelfSignedCert() error {
	log.Info("configuring TLS with self signed certificate")
	var handles Handles
	var err error
	defer func() {
		if err != nil {
			service.PruneCerts()
		}
	}()

	rootComposite, err := certs.NewRootComposite()
	if err != nil {
		return utils.TLSConfigurationFailed
	}
	handles.rootCertHandle, err = service.interfacedWsmanMessage.AddTrustedRootCert(rootComposite.StripPem())
	if err != nil {
		return err
	}

	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	derKey, err := service.GetDERKey(handles)
	if derKey == "" {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return utils.TLSConfigurationFailed
	}

	clientComposite, err := certs.NewSignedAMTComposite(derKey, &rootComposite)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	handles.clientCertHandle, err = service.interfacedWsmanMessage.AddClientCert(clientComposite.StripPem())
	if err != nil {
		return err
	}

	log.Debug("TLS rootCertHandle:", handles.rootCertHandle)
	log.Debug("TLS clientCertHandle:", handles.clientCertHandle)
	log.Debug("TLS keyPairHandle:", handles.keyPairHandle)

	err = service.updateTLSCredentialContext(handles)
	if err != nil {
		return utils.TLSConfigurationFailed
	}

	return nil
}

func (service *ProvisioningService) GetDERKey(handles Handles) (derKey string, err error) {
	var keyPairs []publicprivate.RefinedPublicPrivateKeyPair
	keyPairs, err = service.interfacedWsmanMessage.GetPublicPrivateKeyPairs()
	if err != nil {
		return "", err
	}
	for _, keyPair := range keyPairs {
		if keyPair.InstanceID == handles.keyPairHandle {
			derKey = keyPair.DERKey
			break
		}
	}
	return derKey, nil
}

func (service *ProvisioningService) GenerateKeyPair() (handle string, err error) {
	log.Info("generating key pair")
	response, err := service.interfacedWsmanMessage.GenerateKeyPair(publickey.RSA, 2048)
	if err != nil {
		return "", err
	}
	if response.Body.GenerateKeyPair_OUTPUT.ReturnValue != 0 {
		log.Errorf("GenerateKeyPair.ReturnValue: %d", response.Body.GenerateKeyPair_OUTPUT.ReturnValue)
		return "", utils.AmtPtStatusCodeBase
	}
	if len(response.Body.GenerateKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selectors) == 0 {
		log.Error("GenerateKeyPair did not return a valid handle")
		return handle, utils.TLSConfigurationFailed
	}
	handle = response.Body.GenerateKeyPair_OUTPUT.KeyPair.ReferenceParameters.SelectorSet.Selectors[0].Text
	return handle, nil
}

func (service *ProvisioningService) CreateTLSCredentialContext(certHandle string) error {
	log.Info("creating TLS credential context")
	response, err := service.interfacedWsmanMessage.CreateTLSCredentialContext(certHandle)
	log.Trace(response)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "alreadyexists") {
			log.Info("TLSCredentialContext already exists", certHandle)
		} else {
			log.Error("failed creating TLSCredentialContext", certHandle, err)
			return utils.WSMANMessageError
		}
	}
	return nil
}

func (service *ProvisioningService) EnableTLS() error {
	log.Info("Start TLS configuration : ", service.flags.ConfigTLSInfo.TLSMode.String())

	enumerateRsp, err := service.interfacedWsmanMessage.EnumerateTLSSettingData()
	if err != nil {
		return utils.WSMANMessageError
	}

	pullRsp, err := service.interfacedWsmanMessage.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return utils.WSMANMessageError
	}

	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if item.InstanceID == RemoteTLSInstanceId || item.InstanceID == LocalTLSInstanceId {
			err = service.ConfigureTLSSettings(item)
			if err != nil {
				return err
			}
		}
	}

	service.Pause(service.flags.ConfigTLSInfo.DelayInSeconds)

	_, err = service.interfacedWsmanMessage.CommitChanges()
	if err != nil {
		log.Error("commit changes failed")
		return err
	}
	return nil
}

func (service *ProvisioningService) ConfigureTLSSettings(setting tls.SettingDataResponse) error {
	data, err := getTLSSettings(setting, service.flags.ConfigTLSInfo.TLSMode)
	if err != nil {
		return err
	}
	_, err = service.interfacedWsmanMessage.PUTTLSSettings(data.InstanceID, data)
	if err != nil {
		log.Errorf("failed to configure remote TLS Settings (%s)\n", data.InstanceID)
		return utils.WSMANMessageError
	}
	return nil
}

func getTLSSettings(setting tls.SettingDataResponse, tlsMode flags.TLSMode) (tls.SettingDataRequest, error) {
	data := tls.SettingDataRequest{
		AcceptNonSecureConnections: setting.AcceptNonSecureConnections,
		ElementName:                setting.ElementName,
		Enabled:                    true,
		InstanceID:                 setting.InstanceID,
		MutualAuthentication:       setting.MutualAuthentication,
	}

	log.Infof("configuring TLS settings: %s", setting.InstanceID)
	if setting.NonSecureConnectionsSupported == nil || *setting.NonSecureConnectionsSupported {
		data.AcceptNonSecureConnections = tlsMode == flags.TLSModeServerAndNonTLS || tlsMode == flags.TLSModeMutualAndNonTLS
	}

	if setting.NonSecureConnectionsSupported != nil {
		if tlsMode == flags.TLSModeDisabled && !*setting.NonSecureConnectionsSupported {
			log.Errorf("TLS cannot be disabled on this device")
			return tls.SettingDataRequest{}, utils.TLSConfigurationFailed
		}
	}
	data.MutualAuthentication = tlsMode == flags.TLSModeMutual || tlsMode == flags.TLSModeMutualAndNonTLS
	data.Enabled = tlsMode != flags.TLSModeDisabled

	return data, nil
}

func (service *ProvisioningService) updateTLSCredentialContext(handles Handles) error {
	enumerateRsp, err := service.interfacedWsmanMessage.EnumerateTLSSettingData()
	if err != nil {
		return utils.WSMANMessageError
	}
	pullRsp, err := service.interfacedWsmanMessage.PullTLSSettingData(enumerateRsp.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return utils.WSMANMessageError
	}
	var isRemoteTLSEnabled bool
	var isLocalTLSEnabled bool
	for _, item := range pullRsp.Body.PullResponse.SettingDataItems {
		if item.InstanceID == RemoteTLSInstanceId && item.Enabled {
			isRemoteTLSEnabled = true
		}
		if item.InstanceID == LocalTLSInstanceId && item.Enabled {
			isLocalTLSEnabled = true
		}
	}

	if isRemoteTLSEnabled || isLocalTLSEnabled {
		_, err := service.interfacedWsmanMessage.PutTLSCredentialContext(handles.clientCertHandle)
		if err != nil {
			return err
		}
		_, err = service.interfacedWsmanMessage.CommitChanges()
		if err != nil {
			log.Error("commit changes failed")
			return err
		}
	} else {
		err = service.CreateTLSCredentialContext(handles.clientCertHandle)
		if err != nil {
			return err
		}
	}

	return nil
}
