/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

// recordingStep returns a step that records the AMT password of every call
// and returns errs in order, then nil.
func recordingStep(errs ...error) (stepFunc, *[]string) {
	var passwords []string

	step := func(amtPassword string) error {
		passwords = append(passwords, amtPassword)

		if i := len(passwords) - 1; i < len(errs) {
			return errs[i]
		}

		return nil
	}

	return step, &passwords
}

// nonAuthErr is a step failure with a code other than AMTAuthenticationFailed.
var nonAuthErr error = utils.WSMANMessageError

func TestNewProfileOrchestrator(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "admin123"

	po := NewProfileOrchestrator(cfg, "current-pwd", "mebx-pwd", true)

	if po.currentPassword != "current-pwd" {
		t.Errorf("currentPassword = %q, want %q", po.currentPassword, "current-pwd")
	}

	if po.mebxPassword != "mebx-pwd" {
		t.Errorf("mebxPassword = %q, want %q", po.mebxPassword, "mebx-pwd")
	}

	if !po.skipAMTCertCheck {
		t.Error("skipAMTCertCheck should be true")
	}

	if po.globalPassword != "admin123" {
		t.Errorf("globalPassword = %q, want %q", po.globalPassword, "admin123")
	}
}

func TestNewProfileOrchestrator_TrimSpaces(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "  pwd  ", "  mebx  ", false)

	if po.currentPassword != "pwd" {
		t.Errorf("currentPassword = %q, want %q", po.currentPassword, "pwd")
	}

	if po.mebxPassword != "mebx" {
		t.Errorf("mebxPassword = %q, want %q", po.mebxPassword, "mebx")
	}
}

func TestExecuteWithPasswordFallback_SkippedWhenPreProvisioning(t *testing.T) {
	rotations := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	step, calls := recordingStep(utils.AMTAuthenticationFailed)
	po.currentControlMode = 0 // pre-provisioning: rotation must not happen

	err := po.executeWithPasswordFallback(step)
	if err == nil {
		t.Fatalf("expected auth error to surface, got nil")
	}

	if len(*calls) != 1 {
		t.Errorf("expected 1 call (no rotation in pre-provisioning), got %d", len(*calls))
	}

	require.Empty(t, *rotations)
}

func TestExecuteWithPasswordFallback_UncodedErrorDoesNotRotate(t *testing.T) {
	rotations := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	step, calls := recordingStep(fmt.Errorf("generic failure without a code"))
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback(step)
	if err == nil {
		t.Fatalf("expected error to surface, got nil")
	}

	if len(*calls) != 1 {
		t.Errorf("an error without a code must not trigger rotation, got %d calls", len(*calls))
	}

	require.Empty(t, *rotations)
}

func TestExecuteWithPasswordFallback_NonAuthCodeDoesNotRotate(t *testing.T) {
	rotations := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	step, calls := recordingStep(nonAuthErr)
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback(step)
	if err == nil {
		t.Fatalf("expected error to surface, got nil")
	}

	if len(*calls) != 1 {
		t.Errorf("non-auth code must not trigger rotation, got %d calls", len(*calls))
	}

	require.Empty(t, *rotations)
}

func TestExecuteWithPasswordFallback_AuthCodeTriggersRotationAndRetry(t *testing.T) {
	rotations := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	// Call 0: the step fails with an auth error.
	// Call 1: the step is retried successfully after the in-process
	// rotation using currentPassword.
	step, calls := recordingStep(utils.AMTAuthenticationFailed, nil)
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback(step)
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v", err)
	}

	if len(*calls) != 2 {
		t.Fatalf("expected 2 step calls (fail, retry), got %d", len(*calls))
	}

	// The rotation passes both passwords through the options struct.
	if want := []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "new-pass", false)}; !reflect.DeepEqual(*rotations, want) {
		t.Errorf("rotation options = %+v, want %+v", *rotations, want)
	}

	// The retry gets the new password.
	if (*calls)[1] != "new-pass" {
		t.Errorf("expected retry with new-pass, got: %q", (*calls)[1])
	}
}

func TestExecuteWithPasswordFallback_NoSettleRetryWhenNotActivatedThisRun(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	step, calls := recordingStep(nonAuthErr)
	po.settleDelaySeconds = 0
	// activatedThisRun defaults to false: device was already activated, so a
	// configuration failure is genuine and must fail fast without settle retries.

	err := po.executeWithPasswordFallback(step)
	if err == nil {
		t.Fatalf("expected error to surface, got nil")
	}

	if len(*calls) != 1 {
		t.Errorf("expected 1 call (no settle retry when not activated this run), got %d", len(*calls))
	}
}

func TestExecuteWithPasswordFallback_SettleRetryRecoversAfterActivation(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	// Two transient post-activation failures (dropped connection / locked
	// account), then success once the firmware settles.
	step, calls := recordingStep(nonAuthErr, nonAuthErr, nil)
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	err := po.executeWithPasswordFallback(step)
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v, want nil after settle retry", err)
	}

	if len(*calls) != 3 {
		t.Fatalf("expected 3 calls (fail, fail, succeed), got %d", len(*calls))
	}
}

func TestExecuteWithPasswordFallback_SettleRetryBounded(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	// Every attempt fails; the retry loop must be bounded and then surface the error.
	step, calls := recordingStep(nonAuthErr, nonAuthErr, nonAuthErr, nonAuthErr, nonAuthErr)
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	err := po.executeWithPasswordFallback(step)
	if err == nil {
		t.Fatalf("expected error to surface after exhausting settle retries, got nil")
	}

	if len(*calls) != postActivationSettleAttempts {
		t.Errorf("expected %d calls (bounded settle retries), got %d", postActivationSettleAttempts, len(*calls))
	}
}

func TestExecuteWithPasswordFallback_SettleRetrySkippedForDeviceNotActivated(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	// A device-not-activated failure is not a settling symptom; do not retry.
	step, calls := recordingStep(utils.DeviceNotActivated)
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	err := po.executeWithPasswordFallback(step)
	if err == nil {
		t.Fatalf("expected device-not-activated error to surface, got nil")
	}

	if len(*calls) != 1 {
		t.Errorf("expected 1 call (no settle retry for device-not-activated), got %d", len(*calls))
	}
}

// failingPasswordReader stands in for an interactive prompt. Any read is a test
// failure signal: settle retries must never reach the password prompt.
type failingPasswordReader struct{}

func (r *failingPasswordReader) ReadPassword() (string, error) {
	return "", errors.New("password prompt must not be reached during settle retries")
}

func (r *failingPasswordReader) ReadPasswordWithConfirmation(prompt, confirmPrompt string) (string, error) {
	return "", errors.New("password prompt must not be reached during settle retries")
}

// TestExecuteWithPasswordFallback_SettleRetryDoesNotRePrompt pins the retry path:
// an auth failure in the settle window neither rotates nor prompts, on the
// initial execution or on any settle retry.
func TestExecuteWithPasswordFallback_SettleRetryDoesNotRePrompt(t *testing.T) {
	originalPR := utils.PR
	utils.PR = &failingPasswordReader{}

	defer func() { utils.PR = originalPR }()

	// Every rotation attempt fails with an auth error as well.
	rotations := stubChangeAMTPassword(t, slices.Repeat([]error{utils.AMTAuthenticationFailed}, 32)...)

	cfg := config.Configuration{}
	// An AdminPassword plus control mode 2 is what arms the rotation path.
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	// A supplied current password arms the non-interactive rotation attempt.
	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	// Every call reports an auth failure — the error that triggers rotation. The
	// list is longer than any path through the loop needs, so a rotating retry
	// path cannot pass by simply running out of errors.
	step, _ := recordingStep(slices.Repeat([]error{utils.AMTAuthenticationFailed}, 32)...)
	po.settleDelaySeconds = 0
	po.activatedThisRun = true
	po.currentControlMode = 2

	if err := po.executeWithPasswordFallback(step); err == nil {
		t.Fatalf("expected error to surface after exhausting settle retries, got nil")
	}

	// None: this run activated the device, so a 401 is the settle lockout.
	if len(*rotations) != 0 {
		t.Errorf("expected no rotation attempt in the settle window, got %d", len(*rotations))
	}
}

func TestExecuteWithPasswordFallback_PassesGlobalPassword(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "test-pass"

	po := NewProfileOrchestrator(cfg, "", "", false)
	step, calls := recordingStep()
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback(step)
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v", err)
	}

	if want := []string{"test-pass"}; !reflect.DeepEqual(*calls, want) {
		t.Errorf("step passwords = %v, want %v", *calls, want)
	}
}

// TestStepPassword pins the AMT password every step and the activator get:
// the profile's AdminPassword, else the caller's current password (the old
// child inherited the operator's AMT_PASSWORD), else empty so pkg prompts.
func TestStepPassword(t *testing.T) {
	tests := []struct {
		name            string
		adminPassword   string
		currentPassword string
		want            string
	}{
		{name: "admin password wins", adminPassword: "admin-pass", currentPassword: "current-pass", want: "admin-pass"},
		{name: "current password without admin password", currentPassword: "current-pass", want: "current-pass"},
		{name: "neither", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Configuration{}
			cfg.Configuration.AMTSpecific.AdminPassword = tt.adminPassword
			cfg.Configuration.AMTSpecific.ControlMode = "ccmactivate"

			po := NewProfileOrchestrator(cfg, tt.currentPassword, "", false)
			po.settleDelaySeconds = 0
			activations := stubActivator(po)

			require.NoError(t, po.executeActivation())
			require.Len(t, *activations, 1)
			require.Equal(t, tt.want, (*activations)[0].AMTPassword, "activator")

			// The first call fails while AMT settles, so both the initial
			// call and the settle retry are checked.
			po.activatedThisRun = true
			wifiSync := stubConfigureWiFiSync(t, errors.New("connection reset while AMT settles"))

			require.NoError(t, po.executeEnableWiFi())
			require.Len(t, *wifiSync, 2)

			for i, opts := range *wifiSync {
				require.Equal(t, tt.want, opts.AMTPassword, "wifisync call %d", i)
			}
		})
	}
}
