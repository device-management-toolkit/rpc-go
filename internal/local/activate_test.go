/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	amt2 "github.com/device-management-toolkit/rpc-go/v2/internal/amt"
	"github.com/device-management-toolkit/rpc-go/v2/internal/certs"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var sortaSingletonCerts *certs.CompositeChain = nil

func getTestCerts() *certs.CompositeChain {
	if sortaSingletonCerts == nil {
		cc, _ := certs.NewCompositeChain("P@ssw0rd")
		sortaSingletonCerts = &cc
	}

	return sortaSingletonCerts
}

func TestActivation(t *testing.T) {
	lps := setupService(&flags.Flags{})
	lps.flags.Command = utils.CommandActivate
	lps.flags.LocalConfig.Password = "P@ssw0rd"

	t.Run("return nil activate is success", func(t *testing.T) {
		err := lps.Activate()
		assert.NoError(t, err)
	})

	t.Run("returns UnableToActivate when already activated", func(t *testing.T) {
		lps.flags.ControlMode = 1
		err := lps.Activate()
		assert.Error(t, err)

		lps.flags.ControlMode = 0
	})

	t.Run("returns AMTConnectionFailed when GetLocalSystemAccount fails", func(t *testing.T) {
		mockLocalSystemAccountErr = errTestError
		err := lps.Activate()
		assert.Error(t, err)

		mockLocalSystemAccountErr = nil
	})
}

func TestActivateCCM(t *testing.T) {
	lps := setupService(&flags.Flags{})
	lps.flags.Command = utils.CommandActivate
	lps.flags.LocalConfig.Password = "P@ssw0rd"

	var tlsConfig *tls.Config = nil

	t.Run("returns ActivationFailed on GetGeneralSettings error", func(t *testing.T) {
		errMockGeneralSettings = errTestError
		err := lps.ActivateCCM(tlsConfig)
		assert.Error(t, err)

		errMockGeneralSettings = nil
	})

	t.Run("returns ActivationFailed on HostBasedSetupService", func(t *testing.T) {
		errHostBasedSetupService = errTestError
		err := lps.ActivateCCM(tlsConfig)
		assert.Error(t, err)

		errHostBasedSetupService = nil
	})

	t.Run("returns Success on happy path", func(t *testing.T) {
		err := lps.ActivateCCM(tlsConfig)
		assert.NoError(t, err)
	})

	t.Run("returns Success on happy path with TLS", func(t *testing.T) {
		lps.flags.LocalTlsEnforced = true
		err := lps.ActivateCCM(tlsConfig)
		assert.NoError(t, err)
	})
}

func TestActivateACM(t *testing.T) {
	f := &flags.Flags{}
	f.LocalConfig.ACMSettings.AMTPassword = "P@ssw0rd"
	testCerts := getTestCerts()
	f.LocalConfig.ACMSettings.ProvisioningCert = testCerts.Pfxb64
	f.LocalConfig.ACMSettings.ProvisioningCertPwd = testCerts.PfxPassword
	lps := setupService(f)
	lps.flags.Command = utils.CommandActivate
	lps.flags.LocalConfig.Password = "P@ssw0rd"
	mockCertHashes = []amt2.CertHashEntry{
		{
			Hash:      testCerts.Root.Fingerprint,
			Name:      "",
			Algorithm: "",
			IsActive:  true,
			IsDefault: true,
		},
	}
	err := lps.ActivateACM(true)
	assert.NoError(t, err)
}

func TestInjectCertsErrors(t *testing.T) {
	f := &flags.Flags{}
	testCerts := getTestCerts()

	certs := []string{testCerts.Leaf.Pem, testCerts.Intermediate.Pem, testCerts.Root.Pem}

	t.Run("returns success on injectCerts", func(t *testing.T) {
		lps := setupService(f)
		err := lps.injectCertificate(certs)
		assert.NoError(t, err)
	})
	t.Run("returns error on injectCerts", func(t *testing.T) {
		errAddNextCertInChain = errTestError
		lps := setupService(f)
		err := lps.injectCertificate(certs)
		assert.Error(t, err)

		errAddNextCertInChain = nil
	})
}

func TestDumpPfx(t *testing.T) {
	certsAndKeys := CertsAndKeys{}
	_, _, err := dumpPfx(certsAndKeys)
	assert.NotNil(t, err)

	certsAndKeys.certs = []*x509.Certificate{{}}
	_, _, err = dumpPfx(certsAndKeys)
	assert.NotNil(t, err)
}

// Test for StartSecureHostBasedConfiguration with different certificate algorithms
func TestStartSecureHostBasedConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		certAlgo x509.SignatureAlgorithm
		wantErr  bool
	}{
		{
			name:     "SHA256 algorithm - should succeed",
			certAlgo: x509.SHA256WithRSA,
			wantErr:  false,
		},
		{
			name:     "SHA384 algorithm - should succeed",
			certAlgo: x509.SHA384WithRSA,
			wantErr:  false,
		},
		{
			name:     "Unknown algorithm - should fail",
			certAlgo: x509.UnknownSignatureAlgorithm,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &flags.Flags{}
			service := setupService(f)

			cert := &x509.Certificate{
				SignatureAlgorithm: tt.certAlgo,
				Raw:                []byte("test-cert-data"),
			}

			certsAndKeys := CertsAndKeys{
				certs: []*x509.Certificate{cert},
				keys:  []interface{}{"test-key"},
			}

			_, err := service.StartSecureHostBasedConfiguration(certsAndKeys)

			if (err != nil) != tt.wantErr {
				t.Errorf("StartSecureHostBasedConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test for CompareCertHashes with multi-algorithm support (SHA256 and SHA384)
func TestCompareCertHashes(t *testing.T) {
	testCerts := getTestCerts()

	tests := []struct {
		name       string
		mockHashes []amt2.CertHashEntry
		wantErr    bool
	}{
		{
			name: "SHA256 algorithm match - should succeed",
			mockHashes: []amt2.CertHashEntry{
				{
					Hash:      testCerts.Root.Fingerprint,
					Algorithm: "SHA256",
					IsActive:  true,
					IsDefault: true,
				},
			},
			wantErr: false,
		},
		{
			name: "No matching hash - should fail",
			mockHashes: []amt2.CertHashEntry{
				{
					Hash:      "wronghash1234567890abcdef",
					Algorithm: "SHA256",
					IsActive:  true,
					IsDefault: true,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &flags.Flags{}
			f.LocalConfig.ACMSettings.ProvisioningCert = testCerts.Pfxb64
			f.LocalConfig.ACMSettings.ProvisioningCertPwd = testCerts.PfxPassword
			service := setupService(f)
			mockCertHashes = tt.mockHashes

			// Parse the PFX to get CertsAndKeys
			certsAndKeys, err := convertPfxToObject(testCerts.Pfxb64, testCerts.PfxPassword)
			if err != nil {
				t.Fatalf("Failed to parse PFX: %v", err)
			}

			err = service.CompareCertHashes(certsAndKeys)

			if (err != nil) != tt.wantErr {
				t.Errorf("CompareCertHashes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
