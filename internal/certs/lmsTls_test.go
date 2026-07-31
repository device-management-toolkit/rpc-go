/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/upid"
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
	tests := []struct {
		name                 string
		mode                 int
		skip                 bool
		expectInsecureSkip   bool
		expectPeerVerifyHook bool
	}{
		{
			name:                 "pre-provisioning with verification enabled",
			mode:                 0,
			skip:                 false,
			expectInsecureSkip:   true,
			expectPeerVerifyHook: true,
		},
		{
			name:                 "pre-provisioning with verification skipped",
			mode:                 0,
			skip:                 true,
			expectInsecureSkip:   true,
			expectPeerVerifyHook: true,
		},
		{
			name:                 "ccm-acm with verification enabled",
			mode:                 1,
			skip:                 false,
			expectInsecureSkip:   false,
			expectPeerVerifyHook: false,
		},
		{
			name:                 "ccm-acm with verification skipped",
			mode:                 1,
			skip:                 true,
			expectInsecureSkip:   true,
			expectPeerVerifyHook: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := GetTLSConfig(&tt.mode, nil, tt.skip, nil)
			assert.NotNil(t, tlsConfig)
			assert.Equal(t, tt.expectInsecureSkip, tlsConfig.InsecureSkipVerify)

			if tt.expectPeerVerifyHook {
				assert.NotNil(t, tlsConfig.VerifyPeerCertificate)
			} else {
				assert.Nil(t, tlsConfig.VerifyPeerCertificate)
			}
		})
	}
}

func TestVerifyUPIDBinding(t *testing.T) {
	romTemplate := createCertTemplate("ROM CA", true, []string{"ODCA 2 CSME P"})
	romCert, _ := createTestCert(t, romTemplate, nil, nil)
	romHash := sha256.Sum256(romCert.Raw)

	hwSerial := make([]byte, upid.HWSerialNumSize)
	copy(hwSerial[:20], romHash[:20])

	matchingUPID := &upid.UPID{HWSerialNum: hwSerial}
	assert.NoError(t, VerifyUPIDBinding(romCert, matchingUPID))

	hwSerial[0] ^= 0xFF
	mismatchedUPID := &upid.UPID{HWSerialNum: hwSerial}
	assert.Error(t, VerifyUPIDBinding(romCert, mismatchedUPID))
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

func TestVerifyLeafCertificate_WithAMTHashValidation(t *testing.T) {
	leafTemplate := createCertTemplate("iAMT CSME IDevID RCFG", false, []string{"Leaf OU"})
	leafCert, _ := createTestCert(t, leafTemplate, nil, nil)

	sha256Hash := sha256.Sum256(leafCert.Raw)
	sha384Hash := sha512.Sum384(leafCert.Raw)

	tests := []struct {
		name      string
		amtInfo   *amt.SecureHBasedResponse
		shouldErr bool
	}{
		{
			name: "accepts SHA256 hex hash from AMT",
			amtInfo: &amt.SecureHBasedResponse{
				HashAlgorithm: "SHA256",
				AMTCertHash:   strings.ToUpper(hex.EncodeToString(sha256Hash[:])),
			},
			shouldErr: false,
		},
		{
			name: "accepts SHA256 raw bytes from AMT buffer",
			amtInfo: &amt.SecureHBasedResponse{
				HashAlgorithm: "SHA256",
				AMTCertHash:   string(append(sha256Hash[:], make([]byte, 32)...)),
			},
			shouldErr: false,
		},
		{
			name: "accepts SHA384 raw bytes from AMT buffer",
			amtInfo: &amt.SecureHBasedResponse{
				HashAlgorithm: "SHA384",
				AMTCertHash:   string(append(sha384Hash[:], make([]byte, 16)...)),
			},
			shouldErr: false,
		},
		{
			name: "rejects mismatched AMT hash",
			amtInfo: &amt.SecureHBasedResponse{
				HashAlgorithm: "SHA256",
				AMTCertHash:   strings.Repeat("0", 64),
			},
			shouldErr: true,
		},
		{
			name: "rejects mismatched hash with empty algorithm and reports SHA256",
			amtInfo: &amt.SecureHBasedResponse{
				HashAlgorithm: "   ",
				AMTCertHash:   strings.Repeat("0", 64),
			},
			shouldErr: true,
		},
		{
			name: "rejects malformed SHA256 hex hash from AMT",
			amtInfo: &amt.SecureHBasedResponse{
				HashAlgorithm: "SHA256",
				AMTCertHash:   strings.Repeat("Z", 64),
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyLeafCertificate(leafCert, tt.amtInfo)
			if tt.shouldErr {
				assert.Error(t, err)

				if tt.name == "rejects mismatched hash with empty algorithm and reports SHA256" {
					assert.ErrorContains(t, err, "algorithm=SHA256")
				}
			} else {
				assert.NoError(t, err)
			}
		})
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
		{"ROM CA Cert", []string{"Invalid OU Prefix"}, true},
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

func buildUPIDBindingTestChain(t *testing.T) ([][]byte, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	rootTemplate := createCertTemplate("Root CA", true, []string{"Root OU"})
	rootCert, rootKey := createTestCert(t, rootTemplate, nil, nil)

	lastIntermTemplate := createCertTemplate("Last Intermediate", true, []string{"Last Interim OU"})
	lastIntermCert, lastIntermKey := createTestCert(t, lastIntermTemplate, rootCert, rootKey)

	// This certificate signs ROM ODCA and provides issuer OU used by VerifyROMODCACertificate.
	odcaIssuerTemplate := createCertTemplate("ODCA Issuer", true, []string{"ODCA 2 CSME P"})
	odcaIssuerCert, odcaIssuerKey := createTestCert(t, odcaIssuerTemplate, lastIntermCert, lastIntermKey)

	romODCATemplate := createCertTemplate("ROM CA", true, []string{"ROM OU"})
	romODCACert, romODCAKey := createTestCert(t, romODCATemplate, odcaIssuerCert, odcaIssuerKey)

	interm2Template := createCertTemplate("Intermediate 2", true, []string{"Intermediate 2 OU"})
	interm2Cert, interm2Key := createTestCert(t, interm2Template, romODCACert, romODCAKey)

	interm1Template := createCertTemplate("Intermediate 1", true, []string{"Intermediate 1 OU"})
	interm1Cert, interm1Key := createTestCert(t, interm1Template, interm2Cert, interm2Key)

	leafTemplate := createCertTemplate("iAMT CSME IDevID RCFG", false, []string{"Leaf OU"})
	leafCert, _ := createTestCert(t, leafTemplate, interm1Cert, interm1Key)

	mockFS := &mockFileSystem{
		certFiles: []string{"root.cer"},
		certData:  map[string][]byte{"trustedstore/root.cer": rootCert.Raw},
	}

	oldLoadRootCAPool := LoadRootCAPool
	LoadRootCAPool = func() (*x509.CertPool, error) {
		return LoadRootCAPoolwithFS(mockFS)
	}

	t.Cleanup(func() {
		LoadRootCAPool = oldLoadRootCAPool
	})

	rawCerts := [][]byte{
		leafCert.Raw,
		interm1Cert.Raw,
		interm2Cert.Raw,
		romODCACert.Raw,
		odcaIssuerCert.Raw,
		lastIntermCert.Raw,
	}

	return rawCerts, leafCert, romODCACert
}

func TestVerifyCertificates_UPIDBinding_Success(t *testing.T) {
	mode := 0
	rawCerts, leafCert, romODCACert := buildUPIDBindingTestChain(t)

	romHash := sha256.Sum256(romODCACert.Raw)
	hwSerial := make([]byte, upid.HWSerialNumSize)
	copy(hwSerial[:20], romHash[:20])
	upidInfo := &upid.UPID{HWSerialNum: hwSerial}

	leafHash := sha256.Sum256(leafCert.Raw)
	amtCertInfo := &amt.SecureHBasedResponse{
		HashAlgorithm: hashAlgorithmSHA256,
		AMTCertHash:   strings.ToUpper(hex.EncodeToString(leafHash[:])),
	}

	err := VerifyCertificates(rawCerts, &mode, amtCertInfo, upidInfo)
	assert.NoError(t, err)
}

func TestVerifyCertificates_UPIDBinding_Mismatch(t *testing.T) {
	mode := 0
	rawCerts, leafCert, romODCACert := buildUPIDBindingTestChain(t)

	romHash := sha256.Sum256(romODCACert.Raw)
	hwSerial := make([]byte, upid.HWSerialNumSize)
	copy(hwSerial[:20], romHash[:20])
	hwSerial[0] ^= 0xFF
	upidInfo := &upid.UPID{HWSerialNum: hwSerial}

	leafHash := sha256.Sum256(leafCert.Raw)
	amtCertInfo := &amt.SecureHBasedResponse{
		HashAlgorithm: hashAlgorithmSHA256,
		AMTCertHash:   strings.ToUpper(hex.EncodeToString(leafHash[:])),
	}

	err := VerifyCertificates(rawCerts, &mode, amtCertInfo, upidInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "UPID CSME HW ID does not match ROM ODCA certificate hash")
}
