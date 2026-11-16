/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

// stubActivator sets an activator on po that records each call and returns
// errs[i] for the i-th call (nil once errs is exhausted).
func stubActivator(po *ProfileOrchestrator, errs ...error) *[]LocalActivation {
	var calls []LocalActivation

	po.SetActivator(func(a LocalActivation) error {
		calls = append(calls, a)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	})

	return &calls
}

// acmProfile is an ACM profile with a provisioning certificate.
func acmProfile() config.Configuration {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.ProvisioningCert = "cert-data"
	cfg.Configuration.AMTSpecific.ProvisioningCertPwd = "cert-pwd"

	return cfg
}

func TestExecuteActivation_ACM_WithMEBxFromProfile(t *testing.T) {
	cfg := acmProfile()
	cfg.Configuration.AMTSpecific.MEBXPassword = "profile-mebx"

	po := NewProfileOrchestrator(cfg, "", "cli-mebx", false)
	executor := newMockExecutor()
	po.executor = executor
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())

	require.Equal(t, []LocalActivation{{
		ACM:                      true,
		ProvisioningCert:         "cert-data",
		ProvisioningCertPassword: "cert-pwd",
		MEBxPassword:             "profile-mebx",
	}}, *calls)
	require.Equal(t, 0, executor.callCount, "activation must not run the CLI")
}

func TestExecuteActivation_ACM_WithMEBxFromCLI(t *testing.T) {
	po := NewProfileOrchestrator(acmProfile(), "", "cli-mebx", false)
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())

	require.Equal(t, []LocalActivation{{
		ACM:                      true,
		ProvisioningCert:         "cert-data",
		ProvisioningCertPassword: "cert-pwd",
		MEBxPassword:             "cli-mebx",
	}}, *calls)
}

func TestExecuteActivation_ACM_NoMEBx(t *testing.T) {
	po := NewProfileOrchestrator(acmProfile(), "", "", false)
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())

	require.Equal(t, []LocalActivation{{
		ACM:                      true,
		ProvisioningCert:         "cert-data",
		ProvisioningCertPassword: "cert-pwd",
	}}, *calls)
}

func TestExecuteActivation_CCM_NoMEBx(t *testing.T) {
	// A CCM profile gets neither the MEBx password (profile or CLI) nor the
	// provisioning certificate, as the old child got none of them.
	cfg := acmProfile()
	cfg.Configuration.AMTSpecific.ControlMode = "ccmactivate"
	cfg.Configuration.AMTSpecific.MEBXPassword = "profile-mebx"

	po := NewProfileOrchestrator(cfg, "", "some-mebx", true)
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())

	require.Equal(t, []LocalActivation{{SkipAMTCertCheck: true}}, *calls)
}

func TestExecuteActivation_PassesAllPasswords(t *testing.T) {
	cfg := acmProfile()
	cfg.Configuration.AMTSpecific.MEBXPassword = "mebx-pwd"
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pwd"

	po := NewProfileOrchestrator(cfg, "", "", true)
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())

	require.Equal(t, []LocalActivation{{
		ACM:                      true,
		ProvisioningCert:         "cert-data",
		ProvisioningCertPassword: "cert-pwd",
		AMTPassword:              "admin-pwd",
		MEBxPassword:             "mebx-pwd",
		SkipAMTCertCheck:         true,
	}}, *calls)
}

func TestExecuteActivation_UsesCurrentGlobalPassword(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = "ccmactivate"
	cfg.Configuration.AMTSpecific.AdminPassword = "profile-pwd"

	po := NewProfileOrchestrator(cfg, "", "", false)
	po.globalPassword = "rotated-pwd"
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())

	require.Equal(t, []LocalActivation{{AMTPassword: "rotated-pwd"}}, *calls)
}

func TestExecuteActivation_SkipsWithoutControlMode(t *testing.T) {
	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)
	calls := stubActivator(po)

	require.NoError(t, po.executeActivation())
	require.Empty(t, *calls)
}

func TestExecuteActivation_RejectsUnsupportedControlMode(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = "bogus"

	po := NewProfileOrchestrator(cfg, "", "", false)
	calls := stubActivator(po)

	require.EqualError(t, po.executeActivation(), "unsupported control mode: bogus")
	require.Empty(t, *calls)
}

func TestExecuteActivation_NoActivator(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = "ccmactivate"

	po := NewProfileOrchestrator(cfg, "", "", false)
	executor := newMockExecutor()
	po.executor = executor

	require.ErrorIs(t, po.executeActivation(), errNoActivator)
	require.Equal(t, 0, executor.callCount, "activation must not fall back to the CLI")
}

func TestExecuteActivation_ReturnsActivatorErrorWithoutRetry(t *testing.T) {
	// Activation calls the activator once, with no rotation or settle retry,
	// as it ran the executor once before.
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = "ccmactivate"
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pwd"

	po := NewProfileOrchestrator(cfg, "old-pwd", "", false)
	po.activatedThisRun = true
	po.settleDelaySeconds = 0
	calls := stubActivator(po, utils.AMTAuthenticationFailed)

	require.ErrorIs(t, po.executeActivation(), utils.AMTAuthenticationFailed)
	require.Len(t, *calls, 1)
}

func TestExecuteActivation_UpgradeAuthFailureDoesNotRotate(t *testing.T) {
	// CCM -> ACM upgrade: an activated device with a profile AdminPassword is
	// where a rotation wrapper would fire. Activation must not rotate.
	cfg := acmProfile()
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pwd"

	po := NewProfileOrchestrator(cfg, "old-pwd", "", false)
	po.currentControlMode = 1
	po.settleDelaySeconds = 0
	rotations := stubChangeAMTPassword(t, nil)
	calls := stubActivator(po, utils.AMTAuthenticationFailed)

	require.ErrorIs(t, po.executeActivation(), utils.AMTAuthenticationFailed)
	require.Len(t, *calls, 1)
	require.Empty(t, *rotations)
}
