/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
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

	tlsConfig := &tls.Config{}
	if service.flags.LocalTlsEnforced {
		tlsConfig = config.GetTLSConfig(&service.flags.ControlMode, nil, service.flags.SkipCertCheck)

		// Add client certificate for mutual TLS if provisioning cert is provided
		// This is required for AMT 19+ in ACM mode
		if service.flags.LocalConfig.ACMSettings.ProvisioningCert != "" &&
			service.flags.LocalConfig.ACMSettings.ProvisioningCertPwd != "" {
			log.Trace("Adding client certificate for mutual TLS")

			pfx, err := base64.StdEncoding.DecodeString(service.flags.LocalConfig.ACMSettings.ProvisioningCert)
			if err != nil {
				log.Error("Failed to decode provisioning certificate: ", err)

				return utils.ActivationFailedDecode64
			}

			privateKey, certificate, extraCerts, err := pkcs12.DecodeChain(pfx, service.flags.LocalConfig.ACMSettings.ProvisioningCertPwd)
			if err != nil {
				log.Error("Failed to decode certificate chain: ", err)

				return utils.ActivationFailedInvalidProvCert
			}

			// Order certificate chain properly
			certs := append([]*x509.Certificate{certificate}, extraCerts...)

			orderedCerts, err := utils.OrderCertsChain(certs)
			if err != nil {
				log.Error("Failed to order certificate chain: ", err)

				return utils.ActivationFailedInvalidProvCert
			}

			// Build certificate chain
			var certChain [][]byte
			for _, cert := range orderedCerts {
				certChain = append(certChain, cert.Raw)
			}

			tlsCert := tls.Certificate{
				Certificate: certChain,
				PrivateKey:  privateKey,
				Leaf:        orderedCerts[0],
			}

			tlsConfig.Certificates = []tls.Certificate{tlsCert}

			// Set GetClientCertificate callback for proper client certificate selection
			clientCert := tlsCert
			tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				log.Trace("Client certificate requested by server for deactivation")

				return &clientCert, nil
			}
		}
	}

	err = service.interfacedWsmanMessage.SetupWsmanClient("admin", service.flags.Password, service.flags.LocalTlsEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)
	if err != nil {
		return err
	}

	if service.flags.PartialUnprovision {
		_, err := service.interfacedWsmanMessage.PartialUnprovision()
		if err != nil {
			log.Error("Status: Unable to partially deactivate ", err)

			return utils.UnableToDeactivate
		}
	} else {
		_, err = service.interfacedWsmanMessage.Unprovision(1)
		if err != nil {
			log.Error("Status: Unable to deactivate ", err)

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
