/*********************************************************************
 * Copyright (c) Intel Corporation 2021
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package utils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupEnvOrString_Default(t *testing.T) {
	result := LookupEnv("URL")
	assert.Equal(t, "", result)
}

func TestInterpretControlMode(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"Mode0", 0, "pre-provisioning state"},
		{"Mode1", 1, "activated in client control mode"},
		{"Mode2", 2, "activated in admin control mode"},
		{"Mode3", 3, "unknown state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretControlMode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterpretHashAlgorithm(t *testing.T) {
	tests := []struct {
		name         string
		input        int
		expectedAlg  string
		expectedSize int
	}{
		{"Hash0", 0, "MD5", 16},
		{"Hash1", 1, "SHA1", 20},
		{"Hash2", 2, "SHA256", 32},
		{"Hash3", 3, "SHA384", 48},
		{"Hash4", 4, "UNKNOWN", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, alg := InterpretHashAlgorithm(tt.input)
			assert.Equal(t, tt.expectedAlg, alg)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}

func TestInterpretRemoteAccessTrigger(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"Trigger0", 0, "user initiated"},
		{"Trigger1", 1, "alert"},
		{"Trigger2", 2, "periodic"},
		{"Trigger3", 3, "provisioning"},
		{"Trigger4", 4, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretRemoteAccessTrigger(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterpretAMTNetworkConnectionStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"Status0", 0, "direct"},
		{"Status1", 1, "vpn"},
		{"Status2", 2, "outside enterprise"},
		{"Status3", 3, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretAMTNetworkConnectionStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInterpretRemoteAccessConnectionStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"ConnStatus0", 0, "not connected"},
		{"ConnStatus1", 1, "connecting"},
		{"ConnStatus2", 2, "connected"},
		{"ConnStatus3", 3, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InterpretRemoteAccessConnectionStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateMPSPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		// Valid passwords
		{"ValidAllRequirements", "P@ssw0rd!", false},
		{"ValidWith16Chars", "Aa1!Aa1!Aa1!Aa1!", false},
		{"ValidMinLength", "A1a!a2B#", false},

		// Invalid due to length
		{"TooShort", "A1a!", true},
		{"TooLong", "A1a!A1a!A1a!A1a!A", true},

		// Invalid due to missing character types
		{"MissingUppercase", "p@ssw0rd", true},
		{"MissingLowercase", "P@SSW0RD", true},
		{"MissingDigit", "P@ssword", true},
		{"MissingSpecial", "Passw0rd", true},

		// Edge case: exactly one missing type
		{"OnlyUppercase", "PASSWORD", true},
		{"OnlyLowercase", "password", true},
		{"OnlyDigits", "12345678", true},
		{"OnlySpecial", "!@#$%^&*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMPSPassword(tt.password)
			if tt.expectError {
				assert.True(t, errors.Is(err, IncorrectCommandLineParameters), "expected IncorrectCommandLineParameters error")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckCertificateAlgorithmSupported(t *testing.T) {
	tests := []struct {
		name          string
		algorithm     x509.SignatureAlgorithm
		expectedValue uint8
		expectError   bool
	}{
		// Supported cases
		{"MD5WithRSA", x509.MD5WithRSA, 0, false},
		{"SHA1WithRSA", x509.SHA1WithRSA, 1, false},
		{"DSAWithSHA1", x509.DSAWithSHA1, 1, false},
		{"ECDSAWithSHA1", x509.ECDSAWithSHA1, 1, false},
		{"SHA256WithRSA", x509.SHA256WithRSA, 2, false},
		{"DSAWithSHA256", x509.DSAWithSHA256, 2, false},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, 2, false},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, 2, false},
		{"SHA384WithRSA", x509.SHA384WithRSA, 3, false},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, 3, false},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, 3, false},

		// Unsupported cases
		{"UnknownSignatureAlgorithm", x509.UnknownSignatureAlgorithm, 99, true},
		{"MD2WithRSA", x509.MD2WithRSA, 99, true},
		{"PureEd25519", x509.PureEd25519, 99, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := CheckCertificateAlgorithmSupported(tt.algorithm)
			assert.Equal(t, tt.expectedValue, value)

			if tt.expectError {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, ErrUnsupportedCertAlgorithm), "should match expected error type")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCleanPEM(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "Basic PEM with headers and newlines",
			input: `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8WQ
-----END CERTIFICATE-----`,
			expected: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8WQ",
		},
		{
			name: "PEM with multiple newlines",
			input: `-----BEGIN CERTIFICATE-----
MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8WQ
-----END CERTIFICATE-----`,
			expected: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8WQ",
		},
		{
			name:     "PEM without headers",
			input:    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8WQ",
			expected: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8WQ",
		},
		{
			name:     "Empty input",
			input:    "",
			expected: "",
		},
		{
			name: "Only headers",
			input: `-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CleanPEM(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()

	assert.NoError(t, err, "should not return an error")
	assert.NotNil(t, nonce, "nonce should not be nil")
	assert.Equal(t, 20, len(nonce), "nonce should be exactly 20 bytes long")
}

// mockCert creates a fake *x509.Certificate with minimal fields set
func mockCert(subject, issuer string, isCA bool) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkixName(subject),
		Issuer:  pkixName(issuer),
		IsCA:    isCA,
		Raw:     []byte(subject), // just to differentiate in ordered output
	}
}

// pkixName simplifies creation of pkix.Name
func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}

func TestOrderCertsChain(t *testing.T) {
	tests := []struct {
		name    string
		certs   []*x509.Certificate
		wantCNs []string
		wantErr error
	}{
		{
			name: "valid leaf → intermediate → root",
			certs: []*x509.Certificate{
				mockCert("leaf", "intermediate", false),
				mockCert("intermediate", "root", true),
				mockCert("root", "root", true),
			},
			wantCNs: []string{"leaf", "intermediate", "root"},
		},
		{
			name: "valid leaf → root -> intermediate",
			certs: []*x509.Certificate{
				mockCert("leaf", "intermediate", false),
				mockCert("root", "root", true),
				mockCert("intermediate", "root", true),
			},
			wantCNs: []string{"leaf", "intermediate", "root"},
		},
		{
			name: "valid root → leaf → intermediate",
			certs: []*x509.Certificate{
				mockCert("root", "root", true),
				mockCert("leaf", "intermediate", false),
				mockCert("intermediate", "root", true),
			},
			wantCNs: []string{"leaf", "intermediate", "root"},
		},
		{
			name: "valid intermediate → root → leaf ",
			certs: []*x509.Certificate{
				mockCert("intermediate", "root", true),
				mockCert("root", "root", true),
				mockCert("leaf", "intermediate", false),
			},
			wantCNs: []string{"leaf", "intermediate", "root"},
		},
		{
			name: "incomplete chain (missing parent)",
			certs: []*x509.Certificate{
				mockCert("leaf", "intermediate", false),
			},
			wantErr: errors.New("incomplete certificate chain"),
		},
		{
			name: "cycle in chain",
			certs: []*x509.Certificate{
				mockCert("leaf", "intermediate", false),
				mockCert("intermediate", "leaf", true),
			},
			wantErr: errors.New("cycle detected in certificate chain"),
		},
		{
			name: "multiple leaves",
			certs: []*x509.Certificate{
				mockCert("leaf1", "intermediate", false),
				mockCert("leaf2", "intermediate", false),
				mockCert("intermediate", "root", true),
				mockCert("root", "root", true),
			},
			wantErr: errors.New("multiple possible leaf certificates"),
		},
		{
			name: "no leaf",
			certs: []*x509.Certificate{
				mockCert("root", "root", true),
				mockCert("intermediate", "root", true),
			},
			wantErr: errors.New("no valid leaf certificate"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ordered, err := OrderCertsChain(tt.certs)
			if tt.wantErr != nil {
				if err == nil || !contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("expected error containing %q, got %v", tt.wantErr.Error(), err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(ordered) != len(tt.wantCNs) {
				t.Fatalf("expected %d certs, got %d", len(tt.wantCNs), len(ordered))
			}

			for i, cert := range ordered {
				if cert.Subject.CommonName != tt.wantCNs[i] {
					t.Errorf("expected cert[%d] CN = %q, got %q", i, tt.wantCNs[i], cert.Subject.CommonName)
				}
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (needle == haystack || (len(needle) > 0 && string([]rune(haystack)[0:len(needle)]) == needle))
}

func TestDecodeAMT(t *testing.T) {
	testCases := []struct {
		version string
		SKU     string
		want    string
	}{
		{"200", "0", "Invalid AMT version format"},
		{"ab.c", "0", "Invalid AMT version"},
		{"2.0.0", "0", "AMT + ASF + iQST"},
		{"2.1.0", "1", "ASF + iQST"},
		{"2.2.0", "2", "iQST"},
		{"1.1.0", "3", "Unknown"},
		{"3.0.0", "008", "Invalid SKU"},
		{"3.0.0", "8", "AMT"},
		{"4.1.0", "2", "iQST"},
		{"4.0.0", "4", "ASF"},
		{"5.0.0", "288", "TPM Home IT"},
		{"5.0.0", "1088", "WOX"},
		{"5.0.0", "38", "iQST ASF TPM"},
		{"5.0.0", "4", "ASF"},
		{"6.0.0", "2", "iQST"},
		{"7.0.0", "36864", "L3 Mgt Upgrade"},
		{"8.0.0", "24584", "AMT Pro AT-p Corporate"},
		{"10.0.0", "8", "AMT Pro"},
		{"11.0.0", "16392", "AMT Pro Corporate"},
		{"15.0.42", "16392", "AMT Pro Corporate"},
		{"16.1.25", "16400", "Intel Standard Manageability Corporate"},
	}

	for _, tc := range testCases {
		got := DecodeAMTFeatures(tc.version, tc.SKU)
		if got != tc.want {
			t.Errorf("DecodeAMT(%q, %q) = %v; want %v", tc.version, tc.SKU, got, tc.want)
		}
	}
}
