/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Helper function to create test certificates with proper chain of trust
func createTestCert(t *testing.T, template, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// If no parent is provided, create a self-signed certificate
	if parent == nil {
		parent = template
		parentKey = privateKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

func createCertTemplate(commonName string, isCA bool, ou []string) *x509.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: ou,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
}

func TestGetTLSConfig(t *testing.T) {
	mode := 0
	tlsConfig := GetTLSConfig(&mode, nil, true)
	assert.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify)
	assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
	assert.NotNil(t, tlsConfig.VerifyConnection, "VerifyConnection should be set when skipAMTCertCheck is true")

	mode = 1
	tlsConfig = GetTLSConfig(&mode, nil, true)
	assert.NotNil(t, tlsConfig)
	assert.True(t, tlsConfig.InsecureSkipVerify)
	assert.Nil(t, tlsConfig.VerifyPeerCertificate)
	assert.NotNil(t, tlsConfig.VerifyConnection, "VerifyConnection should be set when skipAMTCertCheck is true")

	// Test with skipAMTCertCheck = false
	mode = 0
	tlsConfig = GetTLSConfig(&mode, nil, false)
	assert.NotNil(t, tlsConfig)
	assert.False(t, tlsConfig.InsecureSkipVerify)
	assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
	assert.Nil(t, tlsConfig.VerifyConnection, "VerifyConnection should NOT be set when skipAMTCertCheck is false")

	mode = 1
	tlsConfig = GetTLSConfig(&mode, nil, false)
	assert.NotNil(t, tlsConfig)
	assert.False(t, tlsConfig.InsecureSkipVerify)
	assert.Nil(t, tlsConfig.VerifyPeerCertificate)
	assert.Nil(t, tlsConfig.VerifyConnection, "VerifyConnection should NOT be set when skipAMTCertCheck is false")
}

func TestVerifyLeafCertificate(t *testing.T) {
	tests := []struct {
		cert      *x509.Certificate
		shouldErr bool
	}{
		{createCertTemplate("iAMT CSME IDevID RCFG", false, []string{}), false},
		{createCertTemplate("AMT RCFG", false, []string{}), false},
		{createCertTemplate("Invalid CN", false, []string{}), true},
	}

	for _, tt := range tests {
		err := VerifyLeafCertificate(tt.cert, nil)
		if tt.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestVerifyROMODCACertificate(t *testing.T) {
	tests := []struct {
		cn        string
		issuerOU  []string
		shouldErr bool
	}{
		{"ROM CA Cert", []string{"ODCA 2 CSME P"}, false},
		{"ROM DE Cert", []string{"On Die CSME P"}, false},
		{"Invalid Cert", []string{"Invalid OU"}, true},
	}

	for _, tt := range tests {
		err := VerifyROMODCACertificate(tt.cn, tt.issuerOU)
		if tt.shouldErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

// mockFileSystem is a mock implementation of the FileSystem interface
type mockFileSystem struct {
	certFiles []string
	certData  map[string][]byte
}

// mockDirEntry is a mock implementation of fs.DirEntry
type mockDirEntry struct {
	name string
}

func (m mockDirEntry) Name() string {
	return m.name
}

func (m mockDirEntry) IsDir() bool {
	return false // Return false because we are mocking files, not directories
}

func (m mockDirEntry) Info() (fs.FileInfo, error) {
	// Mock a simple fs.FileInfo object
	return mockFileInfo(m), nil
}

func (m mockDirEntry) Type() fs.FileMode {
	// Mock file type (can be a regular file, directory, etc.)
	return os.ModePerm // Assuming it's a regular file
}

type mockFileInfo struct {
	name string
}

func (m mockFileInfo) Name() string {
	return m.name
}

func (m mockFileInfo) Size() int64 {
	return 0
}

func (m mockFileInfo) Mode() os.FileMode {
	return 0
}

func (m mockFileInfo) ModTime() time.Time {
	return time.Time{}
}

func (m mockFileInfo) IsDir() bool {
	return false
}

func (m mockFileInfo) Sys() interface{} {
	return nil
}

func (m *mockFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	var entries []fs.DirEntry
	for _, file := range m.certFiles {
		entries = append(entries, mockDirEntry{name: file})
	}

	return entries, nil
}

func (m *mockFileSystem) ReadFile(name string) ([]byte, error) {
	// Return certificate data using the full path as the key
	log.Info("mockFileSystem ReadFile: ", name)

	if data, exists := m.certData[name]; exists {
		return data, nil
	}

	return nil, errors.New("file not found: " + name)
}

func TestVerifyFullChain(t *testing.T) {
	// Create the root certificate (7th certificate, used for verification)
	rootTemplate := createCertTemplate("Intel Root CA", true, []string{"Intel Root OU"})
	rootCert, rootKey := createTestCert(t, rootTemplate, nil, nil)

	// Create the last intermediate certificate (6th in chain)
	lastIntermTemplate := createCertTemplate("Last Intermediate CA", true, []string{"Last Intermediate OU"})
	lastIntermCert, lastIntermKey := createTestCert(t, lastIntermTemplate, rootCert, rootKey)

	// Create the 5th certificate
	interm5Template := createCertTemplate("Intermediate CA 5", true, []string{"ODCA 2 CSME P"})
	interm5Cert, interm5Key := createTestCert(t, interm5Template, lastIntermCert, lastIntermKey)

	// Create the ODCA certificate (4th in chain)
	odcaTemplate := createCertTemplate("ROM CA", true, []string{"Intermediate 4 OU"})
	odcaCert, odcaKey := createTestCert(t, odcaTemplate, interm5Cert, interm5Key)

	// Create the 3rd certificate
	interm3Template := createCertTemplate("Intermediate CA 3", true, []string{"Intermediate 3 OU"})
	interm3Cert, interm3Key := createTestCert(t, interm3Template, odcaCert, odcaKey)

	// Create the 2nd certificate
	interm2Template := createCertTemplate("Intermediate CA 2", true, []string{"Intermediate 2 OU"})
	interm2Cert, interm2Key := createTestCert(t, interm2Template, interm3Cert, interm3Key)

	// Create the leaf certificate (1st in chain)
	leafTemplate := createCertTemplate("iAMT CSME IDevID RCFG", false, []string{"Leaf OU"})
	leafCert, _ := createTestCert(t, leafTemplate, interm2Cert, interm2Key)

	// Create another root certificate for negative tests
	rootTemplatex := createCertTemplate("Intel Root CA2", true, []string{"Intel Root OU"})
	rootCertx, rootKeyx := createTestCert(t, rootTemplatex, nil, nil)

	// Create another last intermediate certificate (6th in chain) for negative tests
	lastIntermTemplatex := createCertTemplate("Last Intermediate CA", true, []string{"Last Intermediate OU"})
	lastIntermCertx, _ := createTestCert(t, lastIntermTemplatex, rootCertx, rootKeyx)

	// Mock FileSystem implementation
	mockFileSystem := &mockFileSystem{
		certFiles: []string{
			"root.cer",
		},
		certData: map[string][]byte{
			"trustedstore/root.cer": rootCert.Raw,
		},
	}

	LoadRootCAPool = func() (*x509.CertPool, error) {
		return LoadRootCAPoolwithFS(mockFileSystem)
	}

	tests := []struct {
		name        string
		certs       []*x509.Certificate
		expectError bool
	}{
		{
			name: "Valid full chain",
			certs: []*x509.Certificate{
				leafCert,
				interm2Cert,
				interm3Cert,
				odcaCert,
				interm5Cert,
				lastIntermCert,
			},
			expectError: false,
		},
		{
			name: "Missing intermediate certificates",
			certs: []*x509.Certificate{
				leafCert,
				lastIntermCert,
			},
			expectError: true,
		},
		{
			name: "Invalid Cert chain",
			certs: []*x509.Certificate{
				leafCert,
				interm2Cert,
				interm3Cert,
				odcaCert,
				interm5Cert,
				lastIntermCertx,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyFullChain(tt.certs)
			if tt.expectError && err == nil {
				t.Errorf("%s: Expected error but got none", tt.name)
			}

			if !tt.expectError && err != nil {
				t.Errorf("%s: Unexpected error: %v", tt.name, err)
			}
		})
	}
}
