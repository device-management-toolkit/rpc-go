/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package config

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"

	"github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	log "github.com/sirupsen/logrus"
)

// generates a TLS configuration based on the provided mode.
func GetTLSConfig(mode *int, amtCertInfo *amt.SecureHBasedResponse, skipCertCheck bool) *tls.Config {
	tlsConfig := &tls.Config{}

	tlsConfig.InsecureSkipVerify = skipCertCheck

	// When skipping AMT certificate checks, we need to bypass hostname verification as well.
	// AMT 19+ certificates (e.g., CN=AMT RCFG) don't have localhost in their SANs,
	// causing "certificate is not valid for any names" errors even with InsecureSkipVerify=true.
	// VerifyConnection is called after the handshake and allows us to completely bypass validation.
	if skipCertCheck {
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			return nil
		}
	}

	if *mode == 0 { // pre-provisioning mode
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if skipCertCheck {
				return nil
			}

			return VerifyCertificates(rawCerts, mode, amtCertInfo)
		}
	} else {
		// default tls config if device is in ACM or CCM
		log.Trace("Setting default TLS Config for ACM/CCM mode")
	}

	return tlsConfig
}

func VerifyCertificates(rawCerts [][]byte, mode *int, amtCertInfo *amt.SecureHBasedResponse) error {
	numCerts := len(rawCerts)

	const (
		selfSignedChainLength = 1
		prodChainLength       = 6
		odcaCertLevel         = 3
		leafLevel             = 0
	)

	var parsedCerts []*x509.Certificate

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

			log.Infof("Cert[%d]: Subject=%s, Issuer=%s, EKU=%v", i, cert.Subject, cert.Issuer, cert.ExtKeyUsage)

			parsedCerts = append(parsedCerts, cert)

			switch i {
			case leafLevel:
				if err := VerifyLeafCertificate(cert, amtCertInfo); err != nil {
					return err
				}
			case odcaCertLevel:
				if err := VerifyROMODCACertificate(cert.Subject.CommonName, cert.Issuer.OrganizationalUnit); err != nil {
					return err
				}
			} // TODO: verify CRL for each cert
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

// validate the leaf certificate
func VerifyLeafCertificate(cn *x509.Certificate, amtCertInfo *amt.SecureHBasedResponse) error {
	allowedLeafCNs := []string{
		"iAMT CSME IDevID RCFG", "AMT RCFG",
	}

	if amtCertInfo != nil {
		hash := sha256.Sum256(cn.Raw)
		// todo: set length based on algorithm
		if string(hash[:32]) != amtCertInfo.AMTCertHash[:32] {
			return errors.New("hashes don't match")
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

// validate CSME ROM ODCA certificate
func VerifyROMODCACertificate(cn string, issuerOU []string) error {
	allowedOUPrefixes := []string{
		"ODCA 2 CSME P", "On Die CSME P", "ODCA 2 CSME", "On Die CSME",
	}

	if !strings.Contains(cn, "ROM CA") && !strings.Contains(cn, "ROM DE") {
		log.Error("invalid ROM ODCA Certificate: ", cn)

		return errors.New("invalid ROM ODCA Certificate")
	}

	// check that OU of odcaCertLevel must have a prefix equal to either ODCA 2 CSME P or On Die CSME P
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
	rootCAs, err := certs.LoadRootCAPool()
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
