/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"

	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/amt"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/certs"
	log "github.com/sirupsen/logrus"
)

// generates a TLS configuration based on the provided mode.
func GetTLSConfig(mode *int) *tls.Config {
	if *mode == 0 { // pre-provisioning mode
		return &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				return VerifyCertificates(rawCerts, mode)
			},
		}
	}
	// default tls config if device is in ACM or CCM
	log.Trace("Setting default TLS Config for ACM/CCM mode")

	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func VerifyCertificates(rawCerts [][]byte, mode *int) error {
	numCerts := len(rawCerts)

	const (
		selfSignedChainLength = 1
		prodChainLength       = 6
		odcaCertLevel         = 3
		leafLevel             = 0
	)

	var parsedCerts []*x509.Certificate

	if numCerts == prodChainLength {
		for i, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				log.Error("Failed to parse certificate ", i, ": ", err)
				return err
			}

			parsedCerts = append(parsedCerts, cert)

			switch i {
			case leafLevel:
				if err := VerifyLeafCertificate(cert.Subject.CommonName); err != nil {
					return err
				}
			case odcaCertLevel:
				if err := VerifyROMODCACertificate(cert.Subject.CommonName, cert.Issuer.OrganizationalUnit); err != nil {
					return err
				}
			}
			// TODO: verify CRL for each cert
		}
		// verify the full chain
		if err := VerifyFullChain(parsedCerts); err != nil {
			return err
		}

		return nil
	} else if numCerts == selfSignedChainLength {
		return HandleAMTTransition(mode)
	}

	return errors.New("unexpected number of certificates received from AMT: " + strconv.Itoa(numCerts))
}

// validate the leaf certificate
func VerifyLeafCertificate(cn string) error {
	allowedLeafCNs := []string{
		"iAMT CSME IDevID RCFG", "AMT RCFG",
	}
	for _, allowed := range allowedLeafCNs {
		if cn == allowed {
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
