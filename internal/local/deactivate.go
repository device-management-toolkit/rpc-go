/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (service *ProvisioningService) Deactivate() (err error) {
	controlMode, err := service.amtCommand.GetControlMode()
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	// Deactivate based on the control mode
	switch controlMode {
	case 1: // CCMMode
		if service.flags.PartialUnprovision {
			fmt.Println("Partial unprovisioning is only supported in ACM mode")

			return utils.InvalidParameterCombination
		}

		err = service.DeactivateCCM()
	case 2: // ACMMode
		err = service.DeactivateACM()
	default:
		log.Error("Deactivation failed. Device control mode: " + utils.InterpretControlMode(controlMode))

		return utils.UnableToDeactivate
	}

	if err != nil {
		log.Error("Deactivation failed.", err)

		return utils.UnableToDeactivate
	}

	if service.flags.PartialUnprovision {
		log.Info("Status: Device partially deactivated")
	} else {
		log.Info("Status: Device deactivated")
	}

	return nil
}

func (service *ProvisioningService) DeactivateACM() (err error) {
	if service.flags.Password == "" {
		err := service.flags.ReadPasswordFromUser()
		if err != nil {
			return utils.MissingOrIncorrectPassword
		}
	}

	// Build TLS config with client certificate if profile provided
	var tlsConfig *tls.Config

	if service.flags.LocalConfig.ACMSettings.ProvisioningCert != "" &&
		service.flags.LocalConfig.ACMSettings.ProvisioningCertPwd != "" {
		log.Debug("Building TLS config with client certificate from profile for deactivation")

		// Parse the provisioning certificate
		certsAndKeys, err := convertPfxToObject(
			service.flags.LocalConfig.ACMSettings.ProvisioningCert,
			service.flags.LocalConfig.ACMSettings.ProvisioningCertPwd,
		)
		if err != nil {
			log.Error("Failed to parse provisioning certificate: ", err)

			return err
		}

		// Build TLS config with the parsed certificate
		tlsConfig = service.buildTLSConfigWithClientCert(certsAndKeys)
	} else if service.flags.LocalTlsEnforced || service.flags.SkipCertCheck || service.flags.SkipAmtCertCheck {
		// Use TLS config with skip flags for certificate verification bypass
		tlsConfig = config.GetTLSConfig(&service.flags.ControlMode, nil, service.flags.SkipCertCheck || service.flags.SkipAmtCertCheck)

		// Override the GetClientCertificate callback to prevent panic when server requests client cert
		// Return an empty certificate which causes graceful TLS handshake failure instead of panic
		tlsConfig.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			log.Trace("Server requested client certificate for deactivation, but none provided")
			// Return empty cert - server will reject if it requires valid certificate
			return &tls.Certificate{}, nil
		}
	} else {
		// No TLS enforcement and no skip flags - use empty config
		tlsConfig = &tls.Config{}
	}

	err = service.setupWsmanWithConfig("admin", service.flags.Password, tlsConfig)
	if err != nil {
		// Provide helpful message if TLS connection fails
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "certificate required") || strings.Contains(errMsg, "handshake failure") {
			log.Error("TLS connection failed. Provide the provisioning certificate used during activation:")
			log.Error("  sudo ./rpc deactivate -local -configv2 <profile> -configencryptionkey <key>")
		} else if strings.Contains(errMsg, "certificate") || strings.Contains(errMsg, "tls") {
			log.Error("TLS connection failed. Try using -n or -skipamtcertcheck flag:")
			log.Error("  sudo ./rpc deactivate -local -n")
		}
		return err
	}

	if service.flags.PartialUnprovision {
		_, err := service.interfacedWsmanMessage.PartialUnprovision()
		if err != nil {
			// Check if error is due to mutual TLS certificate requirement
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "certificate required") || strings.Contains(errMsg, "handshake failure") {
				log.Error("TLS connection failed. Provide the provisioning certificate used during activation:")
				log.Error("  sudo ./rpc deactivate -local -configv2 <profile> -configencryptionkey <key>")
			} else {
				log.Error("Status: Unable to partially deactivate ", err)
			}

			return utils.UnableToDeactivate
		}
	} else {
		_, err = service.interfacedWsmanMessage.Unprovision(1)
		if err != nil {
			// Check if error is due to mutual TLS certificate requirement
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "certificate required") || strings.Contains(errMsg, "handshake failure") {
				log.Error("TLS connection failed. Provide the provisioning certificate used during activation:")
				log.Error("  sudo ./rpc deactivate -local -configv2 <profile> -configencryptionkey <key>")
			} else {
				log.Error("Status: Unable to deactivate ", err)
			}

			return utils.UnableToDeactivate
		}
	}

	return nil
}

func (service *ProvisioningService) DeactivateCCM() (err error) {
	if service.flags.Password != "" {
		log.Warn("Password not required for CCM deactivation")
	}

	status, err := service.amtCommand.Unprovision()
	if err != nil || status != 0 {
		log.Error("Status: Failed to deactivate ", err)

		return utils.DeactivationFailed
	}

	return nil
}
