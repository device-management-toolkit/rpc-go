/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// stubChangeAMTPassword replaces configureChangeAMTPassword for the test. The
// stub records the options of every call and returns errs in order, then nil.
func stubChangeAMTPassword(t *testing.T, errs ...error) *[]configure.AMTPasswordOptions {
	t.Helper()

	var calls []configure.AMTPasswordOptions

	orig := configureChangeAMTPassword
	configureChangeAMTPassword = func(opts configure.AMTPasswordOptions) error {
		calls = append(calls, opts)

		if i := len(calls) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	t.Cleanup(func() { configureChangeAMTPassword = orig })

	return &calls
}

// amtPasswordOpts is the options struct a password change from current to
// next is expected to pass to pkg/configure.
func amtPasswordOpts(current, next string, skipAMTCertCheck bool) configure.AMTPasswordOptions {
	return configure.AMTPasswordOptions{
		BaseOptions: configure.BaseOptions{AMTPassword: current, SkipAMTCertCheck: skipAMTCertCheck},
		NewPassword: next,
	}
}

// captureLogs records the standard logger's entries for the test.
func captureLogs(t *testing.T) *logtest.Hook {
	t.Helper()

	hooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))

	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(hooks) })

	return logtest.NewGlobal()
}

// loggedMessage reports whether hook saw an entry with message msg.
func loggedMessage(hook *logtest.Hook, msg string) bool {
	for _, entry := range hook.AllEntries() {
		if entry.Message == msg {
			return true
		}
	}

	return false
}

// fixedPasswordReader answers every password prompt with password.
type fixedPasswordReader struct {
	password string
	reads    int
}

func (r *fixedPasswordReader) ReadPassword() (string, error) {
	r.reads++

	return r.password, nil
}

func (r *fixedPasswordReader) ReadPasswordWithConfirmation(string, string) (string, error) {
	return r.ReadPassword()
}

func TestChangeAMTPassword_MapsOptions(t *testing.T) {
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("skipAMTCertCheck=%t", skip), func(t *testing.T) {
			calls := stubChangeAMTPassword(t)

			po := NewProfileOrchestrator(config.Configuration{}, "", "", skip)

			require.NoError(t, po.changeAMTPassword("old-pass", "new-pass"))

			require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "new-pass", skip)}, *calls)
		})
	}
}

func TestChangeAMTPassword_ReturnsError(t *testing.T) {
	stubChangeAMTPassword(t, utils.AMTAuthenticationFailed)

	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)

	require.ErrorIs(t, po.changeAMTPassword("old-pass", "new-pass"), utils.AMTAuthenticationFailed)
}

func TestVerifyAndAlignAMTPassword_SkipsWithoutAdminPassword(t *testing.T) {
	calls := stubChangeAMTPassword(t)

	po := NewProfileOrchestrator(config.Configuration{}, "current-pass", "", false)
	po.currentControlMode = 2

	require.NoError(t, po.verifyAndAlignAMTPassword())
	require.Empty(t, *calls)
}

func TestVerifyAndAlignAMTPassword_UpdatesGlobalPasswordOnSuccess(t *testing.T) {
	calls := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-profile-pass"

	po := NewProfileOrchestrator(cfg, "current-pass", "", true)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.verifyAndAlignAMTPassword())

	// One direct change from the caller's current password to the profile's.
	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("current-pass", "new-profile-pass", true)}, *calls)
	require.Equal(t, "new-profile-pass", po.globalPassword)
}

func TestVerifyAndAlignAMTPassword_IdempotentProbe(t *testing.T) {
	calls := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "profile-pass"

	// No current password: the probe changes the password to its own value.
	po := NewProfileOrchestrator(cfg, "", "", false)
	po.currentControlMode = 2

	require.NoError(t, po.verifyAndAlignAMTPassword())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("profile-pass", "profile-pass", false)}, *calls)
}

func TestVerifyAndAlignAMTPassword_ProbesAfterDirectChangeFails(t *testing.T) {
	calls := stubChangeAMTPassword(t, errors.New("direct change failed"))

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "profile-pass"

	po := NewProfileOrchestrator(cfg, "wrong-current", "", true)
	po.currentControlMode = 2

	require.NoError(t, po.verifyAndAlignAMTPassword())

	require.Equal(t, []configure.AMTPasswordOptions{
		amtPasswordOpts("wrong-current", "profile-pass", true),
		amtPasswordOpts("profile-pass", "profile-pass", true),
	}, *calls)
}

func TestVerifyAndAlignAMTPassword_SkipsWhenDeviceNotActivated_WithCurrentPassword(t *testing.T) {
	hook := captureLogs(t)
	calls := stubChangeAMTPassword(t, utils.DeviceNotActivated)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	po.currentControlMode = 2

	require.NoError(t, po.verifyAndAlignAMTPassword())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "new-pass", false)}, *calls)
	require.True(t, loggedMessage(hook, msgPasswordAlignSkipped), "the skip message must be logged")
}

func TestVerifyAndAlignAMTPassword_SkipsWhenDeviceNotActivated_NoCurrentPassword(t *testing.T) {
	hook := captureLogs(t)
	calls := stubChangeAMTPassword(t, utils.DeviceNotActivated)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "", "", false)
	po.currentControlMode = 0 // executeWithPasswordFallback returns original error in pre-provisioning

	require.NoError(t, po.verifyAndAlignAMTPassword())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("new-pass", "new-pass", false)}, *calls)
	require.True(t, loggedMessage(hook, msgPasswordAlignSkipped), "the skip message must be logged")
}

func TestVerifyAndAlignAMTPassword_ProbeAuthFailureRotates(t *testing.T) {
	originalPR := utils.PR
	reader := &fixedPasswordReader{password: "old-pass"}
	utils.PR = reader

	t.Cleanup(func() { utils.PR = originalPR })

	calls := stubChangeAMTPassword(t, utils.AMTAuthenticationFailed)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "profile-pass"

	po := NewProfileOrchestrator(cfg, "", "", false)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.verifyAndAlignAMTPassword())

	// The probe fails with the stale password, the prompted password is
	// rotated to the profile value, and the probe is retried with it.
	require.Equal(t, []configure.AMTPasswordOptions{
		amtPasswordOpts("stale-pass", "profile-pass", false),
		amtPasswordOpts("old-pass", "profile-pass", false),
		amtPasswordOpts("profile-pass", "profile-pass", false),
	}, *calls)
	require.Equal(t, "profile-pass", po.globalPassword)
	require.Equal(t, 1, reader.reads)
}

func TestVerifyAndAlignAMTPassword_ProbeSettleRetry(t *testing.T) {
	t.Run("retries a plain error", func(t *testing.T) {
		calls := stubChangeAMTPassword(t, errors.New("connection reset while AMT settles"))

		cfg := config.Configuration{}
		cfg.Configuration.AMTSpecific.AdminPassword = "profile-pass"

		po := NewProfileOrchestrator(cfg, "", "", false)
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.verifyAndAlignAMTPassword())

		require.Equal(t, []configure.AMTPasswordOptions{
			amtPasswordOpts("profile-pass", "profile-pass", false),
			amtPasswordOpts("profile-pass", "profile-pass", false),
		}, *calls)
	})

	t.Run("stops on device not activated", func(t *testing.T) {
		hook := captureLogs(t)
		calls := stubChangeAMTPassword(t, utils.DeviceNotActivated, utils.DeviceNotActivated)

		cfg := config.Configuration{}
		cfg.Configuration.AMTSpecific.AdminPassword = "profile-pass"

		po := NewProfileOrchestrator(cfg, "", "", false)
		po.currentControlMode = 2
		po.activatedThisRun = true
		po.settleDelaySeconds = 0

		require.NoError(t, po.verifyAndAlignAMTPassword())

		require.Len(t, *calls, 1)
		require.True(t, loggedMessage(hook, msgPasswordAlignSkipped), "the skip message must be logged")
	})
}
