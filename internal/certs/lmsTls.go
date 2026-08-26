/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package certs

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
	log "github.com/sirupsen/logrus"
)

const (
	odca2CSMEPPrefix = "ODCA 2 CSME P"
	onDieCSMEPPrefix = "On Die CSME P"
	odca2CSMEPrefix  = "ODCA 2 CSME"
	onDieCSMEPrefix  = "On Die CSME"
)

const (
	hashAlgorithmSHA256 = "SHA256"
	hashAlgorithmSHA384 = "SHA384"
)

// generates a TLS configuration based on the provided mode.
func GetTLSConfig(mode *int, amtCertInfo *amt.SecureHBasedResponse, skipAMTCertCheck bool, upidInfo *upid.UPID) *tls.Config {
	tlsConfig := &tls.Config{}

	if *mode == 0 { // pre-provisioning mode
		// Use custom ODCA verification for pre-provisioning TLS.
		// We must bypass the default verifier so AMT's activation certificate chain
		// can be validated against the embedded ODCA trust store (without relying on
		// host OS roots / strict EKU checks).
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if skipAMTCertCheck {
				return nil
			}

			return VerifyCertificates(rawCerts, mode, amtCertInfo, upidInfo)
		}
	} else {
		tlsConfig.InsecureSkipVerify = skipAMTCertCheck
		// default tls config if device is in ACM or CCM
		log.Trace("Setting default TLS Config for ACM/CCM mode")
	}

	return tlsConfig
}

func VerifyCertificates(rawCerts [][]byte, mode *int, amtCertInfo *amt.SecureHBasedResponse, upidInfo *upid.UPID) error {
	numCerts := len(rawCerts)

	const (
		selfSignedChainLength = 1
		prodChainLength       = 6
		odcaCertLevel         = 3
		leafLevel             = 0
	)

	var (
		parsedCerts []*x509.Certificate
		romODCACert *x509.Certificate
	)

	switch numCerts {
	case 4:
		fallthrough
	case prodChainLength:
		for i, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				log.Error("Failed to parse certificate ", i, ": ", err)

				return err
			}

			log.Debugf("Cert[%d]: Subject=%s, Issuer=%s, EKU=%v", i, cert.Subject, cert.Issuer, cert.ExtKeyUsage)

			parsedCerts = append(parsedCerts, cert)

			switch i {
			case leafLevel:
				if err := VerifyLeafCertificate(cert, amtCertInfo); err != nil {
					return err
				}
			case odcaCertLevel:
				romODCACert = cert
				if err := VerifyROMODCACertificate(cert.Subject.CommonName, cert.Issuer.OrganizationalUnit); err != nil {
					return err
				}
			}
		}

		if upidInfo != nil {
			if romODCACert == nil {
				return errors.New("failed to identify ROM ODCA certificate for UPID binding verification")
			}

			if err := VerifyUPIDBinding(romODCACert, upidInfo); err != nil {
				return err
			}
		}

		// verify the full chain
		if err := VerifyFullChain(parsedCerts); err != nil {
			return err
		}

		return nil
	case selfSignedChainLength:
		return HandleAMTTransition(mode)
	}

	return errors.New("unexpected number of certificates received from AMT: " + strconv.Itoa(numCerts))
}

func VerifyUPIDBinding(romODCACert *x509.Certificate, upidInfo *upid.UPID) error {
	// Per AMT secure host-based verification, UPID HWSerialNum binds to the
	// first 20 bytes of the SHA-256 hash of the ROM ODCA certificate.
	const upidBindingPrefixLen = 20

	if romODCACert == nil {
		return errors.New("ROM ODCA certificate is required for UPID verification")
	}

	if upidInfo == nil || len(upidInfo.HWSerialNum) < upidBindingPrefixLen {
		return errors.New("UPID data is unavailable or invalid")
	}

	romHash := sha256.Sum256(romODCACert.Raw)
	if !bytes.Equal(romHash[:upidBindingPrefixLen], upidInfo.HWSerialNum[:upidBindingPrefixLen]) {
		return errors.New("UPID CSME HW ID does not match ROM ODCA certificate hash")
	}

	return nil
}

// validate the leaf certificate
func VerifyLeafCertificate(cn *x509.Certificate, amtCertInfo *amt.SecureHBasedResponse) error {
	allowedLeafCNs := []string{
		"iAMT CSME IDevID RCFG", "AMT RCFG",
	}

	if amtCertInfo != nil {
		normalizedAlgo := strings.ToUpper(strings.TrimSpace(amtCertInfo.HashAlgorithm))
		if normalizedAlgo == "" {
			normalizedAlgo = hashAlgorithmSHA256
		}

		expectedHash, err := decodeAMTCertHash(amtCertInfo.AMTCertHash, normalizedAlgo)
		if err != nil {
			return err
		}

		actualHash, err := computeLeafHash(cn.Raw, normalizedAlgo)
		if err != nil {
			return err
		}

		if !bytes.Equal(actualHash, expectedHash) {
			return fmt.Errorf("leaf certificate hash mismatch (algorithm=%s)", normalizedAlgo)
		}
	}

	for _, allowed := range allowedLeafCNs {
		if cn.Subject.CommonName == allowed {
			return nil
		}
	}

	log.Error("leaf certificate CN is not allowed: ", cn)

	return errors.New("leaf certificate CN is not allowed")
}

func computeLeafHash(certRaw []byte, hashAlgorithm string) ([]byte, error) {
	switch strings.ToUpper(strings.TrimSpace(hashAlgorithm)) {
	case "", hashAlgorithmSHA256:
		hash := sha256.Sum256(certRaw)

		return hash[:], nil
	case hashAlgorithmSHA384:
		hash := sha512.Sum384(certRaw)

		return hash[:], nil
	default:
		return nil, fmt.Errorf("unsupported AMT hash algorithm: %s", hashAlgorithm)
	}
}

func decodeAMTCertHash(rawHash string, hashAlgorithm string) ([]byte, error) {
	wireHash := []byte(rawHash)

	hashLen, err := hashLengthForAlgorithm(hashAlgorithm)
	if err != nil {
		return nil, err
	}

	if len(wireHash) < hashLen {
		return nil, errors.New("AMT certificate hash is shorter than expected")
	}

	// Newer firmware can return ASCII hex (64 chars for SHA-256), while other
	// paths can expose raw bytes from the fixed-size PTHI array.
	trimmed := strings.TrimSpace(strings.TrimRight(rawHash, "\x00"))
	if len(trimmed) == hashLen*2 {
		decoded, decErr := hex.DecodeString(trimmed)
		if decErr != nil {
			return nil, fmt.Errorf("failed to decode AMT certificate hash as hex: %w", decErr)
		}

		return decoded, nil
	}

	return wireHash[:hashLen], nil
}

func hashLengthForAlgorithm(hashAlgorithm string) (int, error) {
	switch strings.ToUpper(strings.TrimSpace(hashAlgorithm)) {
	case "", hashAlgorithmSHA256:
		return sha256.Size, nil
	case hashAlgorithmSHA384:
		return sha512.Size384, nil
	default:
		return 0, fmt.Errorf("unsupported AMT hash algorithm: %s", hashAlgorithm)
	}
}

// validate CSME ROM ODCA certificate
func VerifyROMODCACertificate(cn string, issuerOU []string) error {
	allowedOUPrefixes := []string{
		odca2CSMEPPrefix, onDieCSMEPPrefix, odca2CSMEPrefix, onDieCSMEPrefix,
	}

	if !strings.Contains(cn, "ROM CA") && !strings.Contains(cn, "ROM DE") {
		log.Error("invalid ROM ODCA Certificate: ", cn)

		return errors.New("invalid ROM ODCA Certificate")
	}

	// check that OU of odcaCertLevel must have one of the allowed ODCA prefixes
	for _, ou := range issuerOU {
		for _, prefix := range allowedOUPrefixes {
			if strings.HasPrefix(ou, prefix) {
				return nil
			}
		}
	}

	log.Error("ROM ODCA Certificate OU does not have a valid prefix: ", issuerOU)

	return errors.New("ROM ODCA Certificate OU does not have a valid prefix")
}

// validate the full chain
func VerifyFullChain(certificates []*x509.Certificate) error {
	rootCAs, err := LoadRootCAPool()
	if err != nil {
		log.Error("Failed to load root CA pool:", err)

		return err
	}
	// Create a pool for intermediate certificates
	intermediates := x509.NewCertPool()
	for _, cert := range certificates[1:] {
		intermediates.AddCert(cert)
	}

	leafCert := certificates[0]
	opts := x509.VerifyOptions{
		Roots:         rootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	// Validate the full chain (leaf → intermediates → trusted root)
	if _, err := leafCert.Verify(opts); err != nil {
		log.Error("Certificate chain validation failed:", err)

		return err
	}

	return nil
}

// handleAMTTransition - checks if AMT has moved from Pre-Provisioning mode.
func HandleAMTTransition(mode *int) error {
	controlMode, err := amt.NewAMTCommand().GetControlMode()
	if err != nil {
		log.Error("failed to get control mode: ", err)

		return err
	}

	if controlMode != 0 {
		log.Trace("AMT has transitioned to mode: ", controlMode)
		*mode = controlMode

		return nil
	}

	log.Error("unexpected number of certificates received from AMT")

	return errors.New("unexpected number of certificates received from AMT")
}
