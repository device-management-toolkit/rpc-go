/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type CertsAndKeys struct {
	certs []*x509.Certificate
	keys  []interface{}
}

type CertificateObject struct {
	pem     string
	subject string
	issuer  string
}

type ProvisioningCertObj struct {
	certChain            []string
	privateKey           crypto.PrivateKey
	certificateAlgorithm x509.SignatureAlgorithm
}

func (service *ProvisioningService) Activate() error {
	// Check if the device is already activated
	if service.flags.ControlMode != 0 {
		log.Error("Device is already activated")

		return utils.UnableToActivate
	}

	err := service.CheckAndEnableAMT(service.flags.SkipIPRenew)
	if err != nil {
		return err
	}

	// for local activation, wsman client needs local system account credentials
	lsa, err := service.amtCommand.GetLocalSystemAccount()
	if err != nil {
		log.Error(err)

		return utils.AMTConnectionFailed
	}

	tlsConfig := &tls.Config{}

	if service.flags.LocalTlsEnforced {
		if service.flags.UseACM {
			acmConfig := service.config.ACMSettings

			certsAndKeys, err := convertPfxToObject(acmConfig.ProvisioningCert, acmConfig.ProvisioningCertPwd)
			if err != nil {
				return err
			}
			// Use the AMT Certificate response to verify AMT device
			startHBasedResponse, err := service.StartSecureHostBasedConfiguration(certsAndKeys)
			if err != nil {
				return err
			}

			tlsConfig = config.GetTLSConfig(&service.flags.ControlMode, &startHBasedResponse, service.flags.SkipCertCheck)

			// NOTE: Client certificate is NOT added here during initial activation
			// It will be added in ActivateACM() after password change and activation complete
			// Adding it here causes EOF errors on AMT 20/21 during the activation process
		} else {
			tlsConfig = config.GetTLSConfig(&service.flags.ControlMode, nil, service.flags.SkipCertCheck)
		}

		tlsConfig.MinVersion = tls.VersionTLS12
	}

	service.interfacedWsmanMessage.SetupWsmanClient(lsa.Username, lsa.Password, service.flags.LocalTlsEnforced, log.GetLevel() == log.TraceLevel, tlsConfig)

	if service.flags.UseACM {
		err = service.ActivateACM(!service.flags.LocalTlsEnforced)
		if err == nil {
			log.Info("Status: Device activated in Admin Control Mode")
		}
	} else if service.flags.UseCCM {
		err = service.ActivateCCM(tlsConfig)
	}

	return err
}

func (service *ProvisioningService) StartSecureHostBasedConfiguration(certsAndKeys CertsAndKeys) (amt.SecureHBasedResponse, error) {
	// create leaf certificate hash
	var certHashByteArray [64]byte

	leafHash := sha256.Sum256(certsAndKeys.certs[0].Raw)
	copy(certHashByteArray[:], leafHash[:])

	certAlgo, err := utils.CheckCertificateAlgorithmSupported(certsAndKeys.certs[0].SignatureAlgorithm)
	if err != nil {
		return amt.SecureHBasedResponse{}, utils.ActivationFailedCertHash
	}

	// Call StartConfigurationHBased
	params := amt.SecureHBasedParameters{
		CertHash:      certHashByteArray,
		CertAlgorithm: certAlgo,
	}

	response, err := service.amtCommand.StartConfigurationHBased(params)
	if err != nil {
		return amt.SecureHBasedResponse{}, err
	}

	return response, nil
}

func (service *ProvisioningService) ActivateACM(oldWay bool) error {
	if oldWay {
		// Extract the provisioning certificate
		_, certObject, fingerPrint, err := service.GetProvisioningCertObj()
		if err != nil {
			return err
		}
		// Check provisioning certificate is accepted by AMT
		err = service.CompareCertHashes(fingerPrint)
		if err != nil {
			return err
		}

		generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
		if err != nil {
			return utils.ActivationFailedGeneralSettings
		}

		getHostBasedSetupResponse, err := service.interfacedWsmanMessage.GetHostBasedSetupService()
		if err != nil {
			return utils.ActivationFailedSetupService
		}

		decodedNonce := getHostBasedSetupResponse.Body.GetResponse.ConfigurationNonce

		fwNonce, err := base64.StdEncoding.DecodeString(decodedNonce)
		if err != nil {
			return utils.ActivationFailedDecode64
		}

		err = service.injectCertificate(certObject.certChain)
		if err != nil {
			return err
		}

		nonce, err := utils.GenerateNonce()
		if err != nil {
			return err
		}

		signedSignature, err := service.createSignedString(nonce, fwNonce, certObject.privateKey)
		if err != nil {
			return err
		}

		_, err = service.interfacedWsmanMessage.HostBasedSetupServiceAdmin(service.config.ACMSettings.AMTPassword, generalSettings.Body.GetResponse.DigestRealm, nonce, signedSignature)
		if err != nil {
			controlMode, err := service.amtCommand.GetControlMode()
			if err != nil {
				return utils.ActivationFailedGetControlMode
			}

			if controlMode != 2 {
				return utils.ActivationFailedControlMode
			}

			return nil
		}
	} else {
		service.flags.NewPassword = service.config.ACMSettings.AMTPassword

		// Get LSA credentials for initial WSMAN setup
		lsa, err := service.amtCommand.GetLocalSystemAccount()
		if err != nil {
			log.Error("Failed to get LSA credentials:", err)

			return utils.AMTConnectionFailed
		}

		// Declare certsAndKeys at function scope for potential use in rollback
		var certsAndKeys CertsAndKeys

		// Setup WSMAN client with admin credentials and proper TLS config for AMT 19+ support
		// After activation, device is in ACM mode and requires client certificate for TLS
		tlsConfig := config.GetTLSConfig(&service.flags.ControlMode, nil, service.flags.SkipCertCheck)

		if service.flags.LocalTlsEnforced {
			tlsConfig.MinVersion = tls.VersionTLS12

			// Load the provisioning certificate for client authentication
			certsAndKeys, err = convertPfxToObject(service.config.ACMSettings.ProvisioningCert, service.config.ACMSettings.ProvisioningCertPwd)
			if err != nil {
				log.Error("Failed to load provisioning certificate for post-activation:", err)

				return utils.ActivationFailed
			}

			// Build the certificate chain properly
			var certChain [][]byte
			for _, cert := range certsAndKeys.certs {
				certChain = append(certChain, cert.Raw)
			}

			tlsCert := tls.Certificate{
				Certificate: certChain,
				PrivateKey:  certsAndKeys.keys[0],
				Leaf:        certsAndKeys.certs[0],
			}

			tlsConfig.Certificates = []tls.Certificate{tlsCert}

			// Ensure GetClientCertificate callback is set for proper client certificate selection
			clientCert := tlsCert
			tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				log.Trace("Client certificate requested by server (post-activation)")

				return &clientCert, nil
			}
		}

		// Setup WSMAN client with LSA credentials initially (password not yet changed)
		err = service.interfacedWsmanMessage.SetupWsmanClient(
			lsa.Username,
			lsa.Password,
			service.flags.LocalTlsEnforced,
			log.GetLevel() == log.TraceLevel,
			tlsConfig,
		)
		if err != nil {
			log.Error("Failed to setup WSMAN client with LSA credentials:", err)

			return utils.ActivationFailed
		}

		err = service.ChangeAMTPassword()
		if err != nil {
			log.Error("PTHI activation succeeded but password configuration failed:", err.Error())
			log.Warn("Attempting to rollback activation (unprovision device)...")

			// Setup WSMAN client with cert checking disabled for unprovision
			// Use LSA credentials since password was not successfully changed
			rollbackTlsConfig := config.GetTLSConfig(&service.flags.ControlMode, nil, true) // Skip cert check
			rollbackTlsConfig.MinVersion = tls.VersionTLS12

			// Add provisioning cert for client auth
			var certChain [][]byte
			for _, cert := range certsAndKeys.certs {
				certChain = append(certChain, cert.Raw)
			}

			tlsCert := tls.Certificate{
				Certificate: certChain,
				PrivateKey:  certsAndKeys.keys[0],
				Leaf:        certsAndKeys.certs[0],
			}
			rollbackTlsConfig.Certificates = []tls.Certificate{tlsCert}
			clientCert := tlsCert
			rollbackTlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				log.Trace("Client certificate requested by server (rollback)")

				return &clientCert, nil
			}

			// Setup WSMAN client for rollback with LSA credentials
			if setupErr := service.interfacedWsmanMessage.SetupWsmanClient(
				lsa.Username,
				lsa.Password,
				service.flags.LocalTlsEnforced,
				log.GetLevel() == log.TraceLevel,
				rollbackTlsConfig,
			); setupErr != nil {
				log.Error("Failed to setup WSMAN client for rollback:", setupErr)
				log.Error("Manually deactivate and retry activation with -n flag")

				return utils.ActivationFailed
			}

			// Try to unprovision back to pre-provisioning state
			if _, unprovErr := service.interfacedWsmanMessage.Unprovision(1); unprovErr != nil {
				log.Error("Rollback failed - device remains in activated state:", unprovErr)
				log.Error("Manually deactivate and retry activation with -n flag")
			} else {
				log.Info("Rollback successful - device returned to pre-provisioning state")
				log.Info("Retry activation with -n flag")
			}

			return utils.ActivationFailed
		}

		// AMT may close TLS connection after password change
		// Recreate WSMAN client with new password before continuing
		// This is critical for AMT 20/21 which are more sensitive to stale TLS connections
		if service.flags.LocalTlsEnforced {
			log.Debug("Recreating WSMAN client after password change...")

			err = service.interfacedWsmanMessage.SetupWsmanClient(
				"admin",
				service.config.ACMSettings.AMTPassword,
				service.flags.LocalTlsEnforced,
				log.GetLevel() == log.TraceLevel,
				tlsConfig,
			)
			if err != nil {
				log.Error("Failed to recreate WSMAN client after password change:", err)

				return utils.ActivationFailed
			}

			log.Debug("WSMAN client recreated successfully")
		}

		// commit changes
		result, err := service.interfacedWsmanMessage.CommitChanges()
		// AMT may close the connection after CommitChanges as services restart
		// EOF errors during this phase are expected and don't indicate failure
		if err != nil && !strings.Contains(err.Error(), "EOF") {
			log.Error(err.Error())

			return utils.ActivationFailed
		}

		if err == nil {
			log.Debug(result)
		} else {
			log.Debug("AMT services restarting after CommitChanges (connection closed as expected)")
		}

		// Allow AMT services to fully stabilize after CommitChanges
		// This prevents "device did not respond" errors from remote connections
		log.Debug("Waiting for AMT services to stabilize...")
		time.Sleep(5 * time.Second)
		log.Debug("AMT activation complete")
	}

	return nil
}

func (service *ProvisioningService) ActivateCCM(tlsConfig *tls.Config) error {
	generalSettings, err := service.interfacedWsmanMessage.GetGeneralSettings()
	if err != nil {
		return utils.ActivationFailedGeneralSettings
	}

	_, err = service.interfacedWsmanMessage.HostBasedSetupService(generalSettings.Body.GetResponse.DigestRealm, service.config.Password)
	if err != nil {
		return utils.ActivationFailedSetupService
	}

	// If TLS is enforced, commit changes
	if service.flags.LocalTlsEnforced {
		err := service.CCMCommit(tlsConfig)
		if err != nil {
			return utils.ActivationFailed
		}
	}

	log.Info("Status: Device activated in Client Control Mode")

	return nil
}

func (service *ProvisioningService) CCMCommit(tlsConfig *tls.Config) error {
	// Setup WSMAN client with the AMT username and password
	service.interfacedWsmanMessage.SetupWsmanClient(
		"admin",
		service.config.Password,
		service.flags.LocalTlsEnforced,
		log.GetLevel() == log.TraceLevel,
		tlsConfig,
	)

	// commit changes
	_, err := service.interfacedWsmanMessage.CommitChanges()
	if err != nil {
		log.Error("Failed to activate device:", err)

		log.Info("Putting the device back to pre-provisioning mode")

		_, err = service.interfacedWsmanMessage.Unprovision(1)
		if err != nil {
			log.Error("Status: Unable to deactivate ", err)
		}

		return utils.ActivationFailed
	}

	return nil
}

func (service *ProvisioningService) GetProvisioningCertObj() (CertsAndKeys, ProvisioningCertObj, string, error) {
	config := service.config.ACMSettings

	certsAndKeys, err := convertPfxToObject(config.ProvisioningCert, config.ProvisioningCertPwd)
	if err != nil {
		return certsAndKeys, ProvisioningCertObj{}, "", err
	}

	result, fingerprint, err := dumpPfx(certsAndKeys)
	if err != nil {
		return certsAndKeys, ProvisioningCertObj{}, "", err
	}

	return certsAndKeys, result, fingerprint, nil
}

func convertPfxToObject(pfxb64, passphrase string) (CertsAndKeys, error) {
	pfx, err := base64.StdEncoding.DecodeString(pfxb64)
	if err != nil {
		return CertsAndKeys{}, utils.ActivationFailedDecode64
	}

	privateKey, certificate, extraCerts, err := pkcs12.DecodeChain(pfx, passphrase)
	if err != nil {
		if strings.Contains(err.Error(), "decryption password incorrect") {
			return CertsAndKeys{}, utils.ActivationFailedWrongCertPass
		}

		return CertsAndKeys{}, utils.ActivationFailedInvalidProvCert
	}

	certs := append([]*x509.Certificate{certificate}, extraCerts...)
	pfxOut := CertsAndKeys{certs: certs, keys: []interface{}{privateKey}}

	pfxOut.certs, err = utils.OrderCertsChain(pfxOut.certs)
	if err != nil {
		return pfxOut, err
	}

	return pfxOut, nil
}

func dumpPfx(pfxobj CertsAndKeys) (ProvisioningCertObj, string, error) {
	if len(pfxobj.certs) == 0 {
		return ProvisioningCertObj{}, "", utils.ActivationFailedNoCertFound
	}

	if len(pfxobj.keys) == 0 {
		return ProvisioningCertObj{}, "", utils.ActivationFailedNoPrivKeys
	}

	var provisioningCertificateObj ProvisioningCertObj

	var certificateList []*CertificateObject

	var fingerprint string

	for _, cert := range pfxobj.certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pem := utils.CleanPEM(string(pem.EncodeToMemory(pemBlock)))
		certificateObject := CertificateObject{pem: pem, subject: cert.Subject.String(), issuer: cert.Issuer.String()}

		// Get the fingerprint from the Root certificate
		if cert.Subject.String() == cert.Issuer.String() {
			der := cert.Raw
			hash := sha256.Sum256(der)
			fingerprint = hex.EncodeToString(hash[:])
		}

		// Put all the certificateObjects into a single list
		certificateList = append(certificateList, &certificateObject)
	}

	if fingerprint == "" {
		return provisioningCertificateObj, "", utils.ActivationFailedNoRootCertFound
	}

	// Add them to the certChain in order
	for _, cert := range certificateList {
		provisioningCertificateObj.certChain = append(provisioningCertificateObj.certChain, cert.pem)
	}

	// Add the private key
	provisioningCertificateObj.privateKey = pfxobj.keys[0]

	// Add the certificate algorithm
	provisioningCertificateObj.certificateAlgorithm = pfxobj.certs[0].SignatureAlgorithm

	return provisioningCertificateObj, fingerprint, nil
}

func (service *ProvisioningService) CompareCertHashes(fingerPrint string) error {
	result, err := service.amtCommand.GetCertificateHashes()
	if err != nil {
		return utils.ActivationFailedGetCertHash
	}

	for _, v := range result {
		if v.Hash == fingerPrint {
			return nil
		}
	}

	return utils.ActivationFailedProvCertNoMatch
}

func (service *ProvisioningService) injectCertificate(certChain []string) error {
	firstIndex := 0
	lastIndex := len(certChain) - 1

	for i, cert := range certChain {
		isLeaf := i == firstIndex
		isRoot := i == lastIndex

		_, err := service.interfacedWsmanMessage.AddNextCertInChain(cert, isLeaf, isRoot)
		if err != nil {
			return utils.ActivationFailedAddCert
		}
	}

	return nil
}

func (service *ProvisioningService) signString(message []byte, privateKey crypto.PrivateKey) (string, error) {
	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("not an RSA private key")
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privatekeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)

	block, _ := pem.Decode([]byte(string(privatekeyPEM)))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("failed to parse private key")
	}

	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", errors.New("failed to sign message")
	}

	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	return signatureBase64, nil
}

func (service *ProvisioningService) createSignedString(nonce, fwNonce []byte, privateKey crypto.PrivateKey) (string, error) {
	arr := append(fwNonce, nonce...)

	signature, err := service.signString(arr, privateKey)
	if err != nil {
		return "", utils.ActivationFailedSignString
	}

	return signature, nil
}
