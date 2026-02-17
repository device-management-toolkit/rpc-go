/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const unknown = "unknown"

var ErrUnsupportedCertAlgorithm = errors.New("unsupported certificate algorithm")

func InterpretControlMode(mode int) string {
	switch mode {
	case 0:
		return "pre-provisioning state"
	case 1:
		return "activated in client control mode"
	case 2:
		return "activated in admin control mode"
	default:
		return unknown + " state"
	}
}

func LookupEnv(key string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return ""
}

func InterpretHashAlgorithm(hashAlgorithm int) (hashSize int, algorithm string) {
	switch hashAlgorithm {
	case 0: // MD5
		hashSize = 16
		algorithm = "MD5"
	case 1: // SHA1
		hashSize = 20
		algorithm = "SHA1"
	case 2: // SHA256
		hashSize = 32
		algorithm = "SHA256"
	case 3: // SHA384
		hashSize = 48
		algorithm = "SHA384"
	default:
		hashSize = 0
		algorithm = "UNKNOWN"
	}

	return hashSize, algorithm
}

func InterpretAMTNetworkConnectionStatus(status int) string {
	switch status {
	case 0:
		return "direct"
	case 1:
		return "vpn"
	case 2:
		return "outside enterprise"
	default:
		return unknown
	}
}

func InterpretRemoteAccessConnectionStatus(status int) string {
	switch status {
	case 0:
		return "not connected"
	case 1:
		return "connecting"
	case 2:
		return "connected"
	default:
		return unknown
	}
}

func InterpretRemoteAccessTrigger(status int) string {
	switch status {
	case 0:
		return "user initiated"
	case 1:
		return "alert"
	case 2:
		return "periodic"
	case 3:
		return "provisioning"
	default:
		return unknown
	}
}

func ValidateMPSPassword(password string) error {
	const (
		minLength = 8
		maxLength = 16
	)

	// Check length constraint
	if length := len(password); length < minLength || length > maxLength {
		return IncorrectCommandLineParameters
	}

	// Check character requirements using regex
	patterns := map[string]string{
		"uppercase": `[A-Z]`,
		"lowercase": `[a-z]`,
		"digit":     `[0-9]`,
		"special":   `[!@#$%^&*()\-=_+\[\]{}|;:'",.<>?/\\\` + "`" + `~]`,
	}

	for patternType, pattern := range patterns {
		matched, err := regexp.MatchString(pattern, password)
		if err != nil {
			return fmt.Errorf("regex error checking for %s: %w", patternType, err)
		}

		if !matched {
			return IncorrectCommandLineParameters
		}
	}

	return nil
}

func CheckCertificateAlgorithmSupported(certAlgorithm x509.SignatureAlgorithm) (value uint8, err error) {
	switch certAlgorithm {
	case x509.MD5WithRSA:
		value = 0
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		value = 1
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		value = 2
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		value = 3
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		value = 5
	case x509.UnknownSignatureAlgorithm, x509.MD2WithRSA, x509.PureEd25519:
		fallthrough
	default:
		value = 99
		err = ErrUnsupportedCertAlgorithm
	}

	return value, err
}

func CleanPEM(pem string) string {
	pem = strings.ReplaceAll(pem, "-----BEGIN CERTIFICATE-----", "")
	pem = strings.ReplaceAll(pem, "-----END CERTIFICATE-----", "")

	return strings.ReplaceAll(pem, "\n", "")
}

func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 20)
	// fills nonce with 20 random bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, ActivationFailedGenerateNonce
	}

	return nonce, nil
}

func OrderCertsChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	certMap := make(map[string]*x509.Certificate)

	var leaf *x509.Certificate

	for _, cert := range certs {
		subject := cert.Subject.String()
		certMap[subject] = cert

		if !cert.IsCA && cert.Subject.String() != cert.Issuer.String() {
			if leaf != nil {
				return nil, fmt.Errorf("multiple possible leaf certificates found")
			}

			leaf = cert
		}
	}

	if leaf == nil {
		return nil, fmt.Errorf("no valid leaf certificate found")
	}

	var ordered []*x509.Certificate

	seen := make(map[string]bool)
	current := leaf

	for {
		subject := current.Subject.String()
		if seen[subject] {
			return nil, fmt.Errorf("cycle detected in certificate chain")
		}

		seen[subject] = true

		ordered = append(ordered, current)

		if subject == current.Issuer.String() {
			break // Reached root
		}

		parent, exists := certMap[current.Issuer.String()]
		if !exists {
			return nil, fmt.Errorf("incomplete certificate chain; missing issuer for %s", subject)
		}

		current = parent
	}

	return ordered, nil
}

// DecodeAMTFeatures decodes AMT features based on version and SKU
func DecodeAMTFeatures(version, sku string) string {
	amtVer, err := parseAMTVersion(version)
	if err != nil {
		if !strings.Contains(version, ".") {
			return "Invalid AMT version format"
		}

		return "Invalid AMT version"
	}

	skuNum, err := strconv.ParseInt(sku, 0, 64)
	if err != nil {
		return "Invalid SKU"
	}

	switch {
	case amtVer <= 2.2:
		return decodeAMTFeaturesV2(skuNum)
	case amtVer < 5.0:
		return decodeAMTFeaturesV3to4(skuNum)
	default:
		return decodeAMTFeaturesV5Plus(skuNum, amtVer)
	}
}

// parseAMTVersion extracts the major version from the AMT version string
func parseAMTVersion(version string) (float64, error) {
	amtParts := strings.Split(version, ".")
	if len(amtParts) <= 1 {
		return 0, fmt.Errorf("invalid version format")
	}

	return strconv.ParseFloat(amtParts[0], 64)
}

// decodeAMTFeaturesV2 handles AMT version 2.2 and below
func decodeAMTFeaturesV2(skuNum int64) string {
	switch skuNum {
	case 0:
		return "AMT + ASF + iQST"
	case 1:
		return "ASF + iQST"
	case 2:
		return "iQST"
	default:
		return "Unknown"
	}
}

// decodeAMTFeaturesV3to4 handles AMT versions 3.0 to 4.x
func decodeAMTFeaturesV3to4(skuNum int64) string {
	result := ""

	if skuNum&0x02 > 0 {
		result += "iQST "
	}

	if skuNum&0x04 > 0 {
		result += "ASF "
	}

	if skuNum&0x08 > 0 {
		result += "AMT"
	}

	return strings.TrimSpace(result)
}

// decodeAMTFeaturesV5Plus handles AMT version 5.0 and above
func decodeAMTFeaturesV5Plus(skuNum int64, amtVer float64) string {
	result := ""

	if skuNum&0x02 > 0 && amtVer < 7.0 {
		result += "iQST "
	}

	if skuNum&0x04 > 0 && amtVer < 6.0 {
		result += "ASF "
	}

	if skuNum&0x08 > 0 {
		result += "AMT Pro "
	}

	if skuNum&0x10 > 0 {
		result += "Intel Standard Manageability "
	}

	if skuNum&0x20 > 0 && amtVer < 6.0 {
		result += "TPM "
	}

	if skuNum&0x100 > 0 && amtVer < 6.0 {
		result += "Home IT "
	}

	if skuNum&0x400 > 0 && amtVer < 6.0 {
		result += "WOX "
	}

	if skuNum&0x2000 > 0 {
		result += "AT-p "
	}

	if skuNum&0x4000 > 0 {
		result += "Corporate "
	}

	if skuNum&0x8000 > 0 && amtVer < 8.0 {
		result += "L3 Mgt Upgrade"
	}

	return strings.TrimSpace(result)
}
