/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/tls"
	"errors"
	"net/url"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/environmentdetection"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Configure() (err error) {
	// Check if the device is already activated
	if service.flags.ControlMode == 0 {
		log.Error("Device is not activated to configure. Please activate the device first.")

		return utils.UnableToConfigure
	}

	tlsConfig := &tls.Config{}
	if service.flags.LocalTlsEnforced {
		tlsConfig = config.GetTLSConfig(&service.flags.ControlMode, nil, service.flags.SkipCertCheck)
	}

	err = service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, service.flags.LocalTlsEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return err
	}

	switch service.flags.SubCommand {
	case utils.SubCommandAddEthernetSettings, utils.SubCommandWired:
		return service.AddEthernetSettings()
	case utils.SubCommandAddWifiSettings, utils.SubCommandWireless:
		return service.AddWifiSettings()
	case utils.SubCommandEnableWifiPort:
		return service.EnableWifiPort(true, true)
	case utils.SubCommandSetMEBx:
		if service.flags.ControlMode != 2 {
			log.Error("Device needs to be in admin control mode to set MEBx password.")

			return utils.UnableToConfigure
		}

		return service.SetMebx()
	case utils.SubCommandConfigureTLS:
		return service.ConfigureTLS()
	case utils.SubCommandSyncClock:
		return service.SynchronizeTime()
	case utils.SubCommandChangeAMTPassword:
		return service.ChangeAMTPassword()
	case utils.SubCommandCIRA:
		return service.EnableCIRA()
	case utils.SubCommandSetAMTFeatures:
		return service.SetAMTFeatures()
	default:
	}

	return utils.IncorrectCommandLineParameters
}

func (service *ProvisioningService) EnableWifiPort(enableSync, enableWiFiSharing bool) (err error) {
	err = service.interfacedWsmanMessage.EnableWiFi(enableSync, enableWiFiSharing)
	if err != nil {
		log.Error("Failed to enable wifi port and local profile synchronization.")

		return err
	}

	log.Info("Successfully enabled wifi port and local profile synchronization.")

	return err
}

func (service *ProvisioningService) ValidateURL(u string) error {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return err
	}

	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return errors.New("url is missing scheme or host")
	}

	return nil
}

func (service *ProvisioningService) ClearCIRA() error {
	rapResults, err := service.interfacedWsmanMessage.GetRemoteAccessPolicies()
	if err != nil {
		return err
	}

	if len(rapResults) > 0 {
		err = service.interfacedWsmanMessage.RemoveRemoteAccessPolicyRules()
		if err != nil {
			return err
		}
	}

	results, err := service.interfacedWsmanMessage.GetMPSSAP()
	if err != nil {
		return err
	}

	for _, result := range results {
		err := service.interfacedWsmanMessage.RemoveMPSSAP(result.Name)
		if err != nil {
			return err
		}
	}

	return nil
}

func (service *ProvisioningService) EnableCIRA() error {
	err := service.ClearCIRA()
	if err != nil {
		return err
	}

	_, err = service.interfacedWsmanMessage.AddTrustedRootCert(service.flags.MPSCert)
	if err != nil {
		if err.Error() == "Root Certificate already exists and must be removed before continuing" {
			log.Warn("Root Certificate already exists. Continuing with the existing certificate.")
		} else {
			return err
		}
	} else {
		log.Info("successfully added the trusted root certificate")
	}

	_, err = service.interfacedWsmanMessage.AddMPS(service.flags.MPSPassword, service.flags.MPSAddress, 4433)
	if err != nil {
		return err
	}

	log.Info("successfully added the mps server")

	results, err := service.interfacedWsmanMessage.GetMPSSAP()
	if err != nil {
		return err
	}

	if len(results) < 1 {
		return errors.New("no MPS found")
	}

	_, err = service.interfacedWsmanMessage.AddRemoteAccessPolicyRule(2, results[0].Name)
	if err != nil {
		return err
	}

	log.Info("successfully added the remote access policy rule for periodic")

	_, err = service.interfacedWsmanMessage.AddRemoteAccessPolicyRule(0, results[0].Name)
	if err != nil {
		return err
	}

	log.Info("successfully added the remote access policy rule for user initiated")

	results6, err := service.interfacedWsmanMessage.GetRemoteAccessPolicies()
	if err != nil {
		return err
	}

	_, err = service.interfacedWsmanMessage.PutRemoteAccessPolicyAppliesToMPS(results6[1])
	if err != nil {
		return err
	}

	log.Info("successfully configured the configured mps for user initiated policy")

	_, err = service.interfacedWsmanMessage.PutRemoteAccessPolicyAppliesToMPS(results6[0])
	if err != nil {
		return err
	}

	log.Info("successfully configured the configured mps for periodic policy")

	_, err = service.interfacedWsmanMessage.RequestStateChangeCIRA()
	if err != nil {
		return err
	}

	log.Info("successfully enabled CIRA")

	results9, err := service.interfacedWsmanMessage.GetEnvironmentDetectionSettings()
	if err != nil {
		return err
	}

	if len(service.flags.EnvironmentDetection) == 0 || service.flags.EnvironmentDetection[0] == "" {
		service.flags.EnvironmentDetection = []string{uuid.NewString() + ".com"}
	}

	data := environmentdetection.EnvironmentDetectionSettingDataRequest{
		DetectionStrings:           service.flags.EnvironmentDetection,
		ElementName:                results9.ElementName,
		InstanceID:                 results9.InstanceID,
		DetectionAlgorithm:         results9.DetectionAlgorithm,
		DetectionIPv6LocalPrefixes: results9.DetectionIPv6LocalPrefixes,
	}

	_, err = service.interfacedWsmanMessage.PutEnvironmentDetectionSettings(data)
	if err != nil {
		return err
	}

	log.Info("successfully configured environment detection settings for CIRA")

	return nil
}
