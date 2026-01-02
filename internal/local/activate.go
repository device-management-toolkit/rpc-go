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
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

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

			tlsCert := tls.Certificate{
				PrivateKey: certsAndKeys.keys[0],
				Leaf:       certsAndKeys.certs[0],
			}

			for _, cert := range certsAndKeys.certs {
				tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
			}

			tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCert)
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

	certAlgo, err := utils.CheckCertificateAlgorithmSupported(certsAndKeys.certs[0].SignatureAlgorithm)
	if err != nil {
		return amt.SecureHBasedResponse{}, utils.ActivationFailedCertHash
	}

	// Generate hash based on certificate algorithm
	switch certAlgo {
	case 2: // SHA256
		leafHash := sha256.Sum256(certsAndKeys.certs[0].Raw)
		copy(certHashByteArray[:], leafHash[:])
	case 3: // SHA384
		leafHash := sha512.Sum384(certsAndKeys.certs[0].Raw)
		copy(certHashByteArray[:], leafHash[:])
	default:
		// Only SHA-256 and SHA-384 are supported for secure host-based configuration
		return amt.SecureHBasedResponse{}, errors.New("unsupported certificate algorithm for activation")
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
		certsAndKeys, certObject, _, err := service.GetProvisioningCertObj()
		if err != nil {
			return err
		}
		// Check provisioning certificate is accepted by AMT
		err = service.CompareCertHashes(certsAndKeys)
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

		err := service.ChangeAMTPassword()
		if err != nil {
			log.Error(err.Error())

			return utils.ActivationFailed
		}

		// commit changes
		result, err := service.interfacedWsmanMessage.CommitChanges()
		if err != nil {
			log.Error(err.Error())

			return utils.ActivationFailed
		}

		log.Debug(result)
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

// compareCertHashes compares certificate hash with AMT stored hashes
// Computes both SHA-256 and SHA-384 fingerprints to support different AMT platforms
func (service *ProvisioningService) CompareCertHashes(certsAndKeys CertsAndKeys) error {
	// Find the root certificate
	var rootCert *x509.Certificate

	for _, cert := range certsAndKeys.certs {
		if cert.Subject.String() == cert.Issuer.String() {
			rootCert = cert

			break
		}
	}

	if rootCert == nil {
		return utils.ActivationFailedNoRootCertFound
	}

	// Compute fingerprints using different hash algorithms
	der := rootCert.Raw

	fingerprints := make(map[string]string)
	// SHA-384 (48 bytes) - Supported by AMT 16.1+
	hashSHA384 := sha512.Sum384(der)
	fingerprints["SHA384"] = hex.EncodeToString(hashSHA384[:])
	// SHA-256 (32 bytes) - Supported by all AMT versions
	hashSHA256 := sha256.Sum256(der)
	fingerprints["SHA256"] = hex.EncodeToString(hashSHA256[:])

	// Get all certificate hashes from AMT
	result, err := service.amtCommand.GetCertificateHashes()
	if err != nil {
		return utils.ActivationFailedGetCertHash
	}

	// Try to match stored hash with corresponding algorithm
	for _, v := range result {
		if v.Algorithm != "" {
			// Algorithm specified: match SHA256 with SHA256, SHA384 with SHA384
			if computedHash, exists := fingerprints[v.Algorithm]; exists {
				if v.Hash == computedHash {
					return nil
				}
			}
		} else {
			// Algorithm not specified: try all computed fingerprints
			for _, computedHash := range fingerprints {
				if v.Hash == computedHash {
					return nil
				}
			}
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
