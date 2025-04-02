/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package local

import (
	"crypto/x509"
	"testing"

	amt2 "github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/amt"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/certs"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/internal/flags"
	"github.com/open-amt-cloud-toolkit/rpc-go/v2/pkg/utils"
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

	t.Run("returns ActivationFailed on GetGeneralSettings error", func(t *testing.T) {
		errMockGeneralSettings = errTestError
		err := lps.ActivateCCM()
		assert.Error(t, err)

		errMockGeneralSettings = nil
	})

	t.Run("returns ActivationFailed on HostBasedSetupService", func(t *testing.T) {
		errHostBasedSetupService = errTestError
		err := lps.ActivateCCM()
		assert.Error(t, err)

		errHostBasedSetupService = nil
	})

	t.Run("returns Success on happy path", func(t *testing.T) {
		err := lps.ActivateCCM()
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
	err := lps.ActivateACM()
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
