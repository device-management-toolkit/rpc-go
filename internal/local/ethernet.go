package local

import (
	"os"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/amt/ethernetport"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/v2/pkg/wsman/ips/ieee8021x"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/config"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) AddEthernetSettings() (err error) {
	var handles Handles
	defer func() {
		if err != nil {
			service.PruneCerts()
		}
	}()

	err = service.verifyInput()
	if err != nil {
		return err
	}

	// Get the current settings
	getResponse, err := service.interfacedWsmanMessage.GetEthernetSettings()
	if err != nil {
		return utils.WiredConfigurationFailed
	}

	// Create the request for the new settings based on the current settings to update AMT
	settingsRequest, err := service.createEthernetSettingsRequest(getResponse[0])
	if err != nil {
		return utils.WiredConfigurationFailed
	}

	// Update the settings in AMT
	_, err = service.interfacedWsmanMessage.PutEthernetSettings(settingsRequest, settingsRequest.InstanceID)
	if err != nil {
		return utils.WiredConfigurationFailed
	}

	err = service.Disable8021xProfile()
	if err != nil {
		return err
	}

	// Check to configure 802.1x, add the certs and update the settings
	if service.config.WiredConfig.Ieee8021xProfileName == "" {
		log.Info("Wired settings configured successfully")
		return nil
	}

	// Configure 802.1x
	// Get the 802.1x settings to configure
	ieee8021xConfig := config.Ieee8021xConfig{}
	for _, curCfg := range service.config.Ieee8021xConfigs {
		if curCfg.ProfileName == service.config.WiredConfig.Ieee8021xProfileName {
			ieee8021xConfig = curCfg
			break
		}
	}

	// Get the current 802.1x settings on AMT
	getIEEESettings, err := service.interfacedWsmanMessage.GetIPSIEEE8021xSettings()
	if err != nil {
		log.Error("Get IPS_IEEE8021xSettings failed", err)
		return utils.WiredConfigurationFailed
	}

	// Check if EA credentials are provided, if so use EA to add the certs, otherwise add the certs given in config
	if service.config.EnterpriseAssistant.EAConfigured {
		handles, ieee8021xConfig, err = service.AddCertsUsingEnterpriseAssistant(ieee8021xConfig)
		if err != nil {
			return utils.WiredConfigurationFailed
		}
	} else {
		handles, err = service.AddCerts(ieee8021xConfig)
		if err != nil {
			return utils.WiredConfigurationFailed
		}
	}

	// Update the 802.1x settings in AMT
	err = service.PutIEEESettings(getIEEESettings, ieee8021xConfig)
	if err != nil {
		return utils.WiredConfigurationFailed
	}
	// Update the 802.1x certs in AMT
	if ieee8021xConfig.AuthenticationProtocol == 0 {
		_, err = service.interfacedWsmanMessage.SetIPSIEEE8021xCertificates(handles.rootCertHandle, handles.clientCertHandle)
		if err != nil {
			log.Errorf("Failed to set 802.1x certificates: %v", err)
			return utils.WiredConfigurationFailed
		}
	}
	log.Info("Wired settings configured with 802.1x successfully")
	return nil
}

func (service *ProvisioningService) Disable8021xProfile() (err error) {
	response, err := service.interfacedWsmanMessage.GetIPSIEEE8021xSettings()
	if err != nil {
		return err
	}

	// Enabled(2) , Disabled(3), Enabled without certificates(6)
	if response.Body.IEEE8021xSettingsResponse.Enabled != 3 {
		request := ieee8021x.IEEE8021xSettingsRequest{
			ElementName: response.Body.IEEE8021xSettingsResponse.ElementName,
			InstanceID:  response.Body.IEEE8021xSettingsResponse.InstanceID,
			Enabled:     3,
		}

		_, err = service.interfacedWsmanMessage.PutIPSIEEE8021xSettings(request)
		if err != nil {
			return err
		}

		//Delete unused certificates
		service.PruneCerts()
	}

	return nil
}

func (service *ProvisioningService) verifyInput() error {
	if service.config.WiredConfig.DHCP == service.config.WiredConfig.Static || (service.config.WiredConfig.DHCP && !service.config.WiredConfig.IpSync) {
		return utils.InvalidParameterCombination
	}

	if service.config.WiredConfig.DHCP {
		if service.config.WiredConfig.IpAddress != "" ||
			service.config.WiredConfig.Subnetmask != "" ||
			service.config.WiredConfig.Gateway != "" ||
			service.config.WiredConfig.PrimaryDNS != "" ||
			service.config.WiredConfig.SecondaryDNS != "" {
			return utils.InvalidParameterCombination
		}
	}

	if service.config.WiredConfig.Static && !service.config.WiredConfig.IpSync {
		if service.config.WiredConfig.IpAddress == "" {
			return utils.MissingOrIncorrectStaticIP
		}
		if service.config.WiredConfig.Subnetmask == "" {
			return utils.MissingOrIncorrectNetworkMask
		}
		if service.config.WiredConfig.Gateway == "" {
			return utils.MissingOrIncorrectGateway
		}
		if service.config.WiredConfig.PrimaryDNS == "" {
			return utils.MissingOrIncorrectPrimaryDNS
		}
	}

	return nil
}

func (service *ProvisioningService) createEthernetSettingsRequest(getResponse ethernetport.SettingsResponse) (request ethernetport.SettingsRequest, err error) {
	settingsRequest := ethernetport.SettingsRequest{
		XMLName:        getResponse.XMLName,
		H:              "",
		ElementName:    getResponse.ElementName,
		InstanceID:     getResponse.InstanceID,
		SharedMAC:      getResponse.SharedMAC,
		SharedStaticIp: getResponse.SharedStaticIp,
		IpSyncEnabled:  getResponse.IpSyncEnabled,
		DHCPEnabled:    getResponse.DHCPEnabled,
		IPAddress:      getResponse.IPAddress,
		SubnetMask:     getResponse.SubnetMask,
		DefaultGateway: getResponse.DefaultGateway,
		PrimaryDNS:     getResponse.PrimaryDNS,
		SecondaryDNS:   getResponse.SecondaryDNS,
	}

	if service.config.WiredConfig.DHCP {
		settingsRequest.DHCPEnabled = true
		settingsRequest.IpSyncEnabled = true
		settingsRequest.SharedStaticIp = false
	} else {
		settingsRequest.DHCPEnabled = false
		settingsRequest.IpSyncEnabled = service.config.WiredConfig.IpSync
		settingsRequest.SharedStaticIp = service.config.WiredConfig.IpSync
	}

	if settingsRequest.IpSyncEnabled {
		settingsRequest.IPAddress = ""
		settingsRequest.SubnetMask = ""
		settingsRequest.DefaultGateway = ""
		settingsRequest.PrimaryDNS = ""
		settingsRequest.SecondaryDNS = ""
	}

	if !service.config.WiredConfig.DHCP && !service.config.WiredConfig.IpSync {
		settingsRequest.IPAddress = service.config.WiredConfig.IpAddress
		settingsRequest.SubnetMask = service.config.WiredConfig.Subnetmask
		settingsRequest.DefaultGateway = service.config.WiredConfig.Gateway
		settingsRequest.PrimaryDNS = service.config.WiredConfig.PrimaryDNS
		settingsRequest.SecondaryDNS = service.config.WiredConfig.SecondaryDNS
	}

	return settingsRequest, nil
}

func (service *ProvisioningService) AddCerts(ieee8021xConfig config.Ieee8021xConfig) (Handles, error) {
	var handles Handles
	var err error
	securitySettings, err := service.GetCertificates()
	if err != nil {
		return handles, utils.WiredConfigurationFailed
	}

	//Add PrivateKey
	handles.privateKeyHandle, err = service.GetPrivateKeyHandle(securitySettings, ieee8021xConfig.PrivateKey)
	if err != nil {
		return handles, utils.WiredConfigurationFailed
	}

	//Add Client Certificate
	handles.clientCertHandle, err = service.GetClientCertHandle(securitySettings, ieee8021xConfig.ClientCert)
	if err != nil {
		return handles, utils.WiredConfigurationFailed
	}

	//Add Trusted Root Certificate
	handles.rootCertHandle, err = service.GetTrustedRootCertHandle(securitySettings, ieee8021xConfig.CACert)
	if err != nil {
		return handles, utils.WiredConfigurationFailed
	}

	return handles, nil
}

func (service *ProvisioningService) AddCertsUsingEnterpriseAssistant(ieee8021xConfig config.Ieee8021xConfig) (Handles, config.Ieee8021xConfig, error) {
	var handles Handles
	securitySettings, err := service.GetCertificates()
	if err != nil {
		return handles, ieee8021xConfig, utils.WiredConfigurationFailed
	}

	credentials := AuthRequest{
		Username: service.config.EnterpriseAssistant.EAUsername,
		Password: service.config.EnterpriseAssistant.EAPassword,
	}
	guid, err := service.amtCommand.GetUUID()
	if err != nil {
		return handles, ieee8021xConfig, err
	}

	// Call GetAuthToken
	url := service.config.EnterpriseAssistant.EAAddress + "/api/authenticate/" + guid
	token, err := service.GetAuthToken(url, credentials)
	if token == "" && err != nil {
		log.Errorf("error getting auth token: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}
	devName, err := os.Hostname()
	if err != nil {
		log.Errorf("error getting auth token: %v", err)
		return handles, ieee8021xConfig, err
	}
	reqProfile := EAProfile{NodeID: guid, Domain: "", ReqID: "", AuthProtocol: ieee8021xConfig.AuthenticationProtocol, OSName: "win11", DevName: devName, Icon: 1, Ver: ""}

	//Request Profile from Microsoft EA
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/profile/" + guid
	reqResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error while requesting EA: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}

	ieee8021xConfig.PrivateKey = ""
	if ieee8021xConfig.AuthenticationProtocol == 2 {
		ieee8021xConfig.ClientCert = ""
		ieee8021xConfig.Username = reqResponse.Response.Username
		ieee8021xConfig.Password = reqResponse.Response.Password
		handles.rootCertHandle, err = service.GetTrustedRootCertHandle(securitySettings, reqResponse.Response.RootCert)
		if err != nil {
			return handles, ieee8021xConfig, utils.WSMANMessageError
		}
		return handles, ieee8021xConfig, nil
	}

	// Generate KeyPair
	handles.keyPairHandle, err = service.GenerateKeyPair()
	if err != nil {
		return handles, ieee8021xConfig, err
	}
	handles.privateKeyHandle = handles.keyPairHandle

	// Get DERkey
	derKey, err := service.GetDERKey(handles)
	if derKey == "" || err != nil {
		log.Errorf("failed matching new amtKeyPairHandle: %s", handles.keyPairHandle)
		return handles, ieee8021xConfig, err
	}

	//Request Profile from Microsoft EA
	reqProfile.DERKey = derKey
	reqProfile.KeyInstanceId = handles.keyPairHandle
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/keypair/" + guid
	KeyPairResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error generating 802.1x keypair: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}

	response, err := service.interfacedWsmanMessage.GeneratePKCS10RequestEx(KeyPairResponse.Response.KeyInstanceId, KeyPairResponse.Response.CSR, 1)
	if err != nil {
		return handles, ieee8021xConfig, utils.WSMANMessageError
	}

	reqProfile.SignedCSR = response.Body.GeneratePKCS10RequestEx_OUTPUT.SignedCertificateRequest
	url = service.config.EnterpriseAssistant.EAAddress + "/api/configure/csr/" + guid
	eaResponse, err := service.EAConfigureRequest(url, token, reqProfile)
	if err != nil {
		log.Errorf("error signing the certificate: %v", err)
		return handles, ieee8021xConfig, utils.Ieee8021xConfigurationFailed
	}
	ieee8021xConfig.Username = eaResponse.Response.Username
	handles.clientCertHandle, err = service.GetClientCertHandle(securitySettings, eaResponse.Response.Certificate)
	if err != nil {
		return handles, ieee8021xConfig, utils.WSMANMessageError
	}

	handles.rootCertHandle, err = service.GetTrustedRootCertHandle(securitySettings, eaResponse.Response.RootCert)
	if err != nil {
		return handles, ieee8021xConfig, utils.WSMANMessageError
	}

	return handles, ieee8021xConfig, nil
}

func (service *ProvisioningService) PutIEEESettings(getIEEESettings ieee8021x.Response, ieee802xCfg config.Ieee8021xConfig) error {
	enabled := 2
	pxeTimeout := 120

	request := ieee8021x.IEEE8021xSettingsRequest{
		AvailableInS0:          true,
		ElementName:            getIEEESettings.Body.IEEE8021xSettingsResponse.ElementName,
		Enabled:                enabled,
		InstanceID:             getIEEESettings.Body.IEEE8021xSettingsResponse.InstanceID,
		PxeTimeout:             pxeTimeout,
		AuthenticationProtocol: ieee802xCfg.AuthenticationProtocol,
		Username:               ieee802xCfg.Username,
	}
	if request.AuthenticationProtocol == 2 {
		request.Password = ieee802xCfg.Password
	}

	putResponse, err := service.interfacedWsmanMessage.PutIPSIEEE8021xSettings(request)
	log.Info("IEEE8021x settings updated successfully")
	log.Debug("IEEE8021x settings: ", putResponse.JSON())
	if err != nil {
		return err
	}
	return nil
}
