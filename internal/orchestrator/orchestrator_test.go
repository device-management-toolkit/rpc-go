/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
)

// mockExecutor records executed commands for verification
type mockExecutor struct {
	executedArgs [][]string
	errOnCall    int // return error on this call index (-1 = never)
	// errs, if non-empty, overrides errOnCall and returns errs[i] for the i-th call
	// (falling back to nil once exhausted).
	errs      []error
	callCount int
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{errOnCall: -1}
}

func (m *mockExecutor) Execute(args []string) error {
	// Copy args to avoid mutation issues
	argsCopy := make([]string, len(args))
	copy(argsCopy, args)
	m.executedArgs = append(m.executedArgs, argsCopy)

	idx := m.callCount
	m.callCount++

	if idx < len(m.errs) {
		return m.errs[idx]
	}

	if m.errOnCall == idx {
		return fmt.Errorf("mock execution error on call %d", idx)
	}

	return nil
}

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

func TestExecuteActivation_ACM_WithMEBxFromProfile(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.ProvisioningCert = "cert-data"
	cfg.Configuration.AMTSpecific.ProvisioningCertPwd = "cert-pwd"
	cfg.Configuration.AMTSpecific.MEBXPassword = "profile-mebx"

	po := NewProfileOrchestrator(cfg, "", "cli-mebx", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeActivation()
	if err != nil {
		t.Fatalf("executeActivation() error = %v", err)
	}

	if len(mock.executedArgs) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(mock.executedArgs))
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	// Profile MEBx password should take precedence
	if !strings.Contains(argsStr, "--mebxpassword profile-mebx") {
		t.Errorf("expected --mebxpassword profile-mebx in args, got: %s", argsStr)
	}
}

func TestExecuteActivation_ACM_WithMEBxFromCLI(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.ProvisioningCert = "cert-data"
	cfg.Configuration.AMTSpecific.ProvisioningCertPwd = "cert-pwd"
	// No MEBXPassword in profile

	po := NewProfileOrchestrator(cfg, "", "cli-mebx", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeActivation()
	if err != nil {
		t.Fatalf("executeActivation() error = %v", err)
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	// CLI MEBx password should be used as fallback
	if !strings.Contains(argsStr, "--mebxpassword cli-mebx") {
		t.Errorf("expected --mebxpassword cli-mebx in args, got: %s", argsStr)
	}
}

func TestExecuteActivation_ACM_NoMEBx(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.ProvisioningCert = "cert-data"
	cfg.Configuration.AMTSpecific.ProvisioningCertPwd = "cert-pwd"

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeActivation()
	if err != nil {
		t.Fatalf("executeActivation() error = %v", err)
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	if strings.Contains(argsStr, "--mebxpassword") {
		t.Errorf("--mebxpassword should not be present when empty, got: %s", argsStr)
	}
}

func TestExecuteActivation_CCM_NoMEBx(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = "ccmactivate"

	po := NewProfileOrchestrator(cfg, "", "some-mebx", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeActivation()
	if err != nil {
		t.Fatalf("executeActivation() error = %v", err)
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	// CCM should not include --mebxpassword
	if strings.Contains(argsStr, "--mebxpassword") {
		t.Errorf("CCM activation should not include --mebxpassword, got: %s", argsStr)
	}
}

func TestExecuteMEBxConfiguration_SkipWhenPreProvisioning(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.MEBXPassword = "mebx-pwd"
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock
	po.currentControlMode = 0 // pre-provisioning

	err := po.executeMEBxConfiguration()
	if err != nil {
		t.Fatalf("executeMEBxConfiguration() error = %v", err)
	}

	// Should have skipped execution entirely
	if len(mock.executedArgs) != 0 {
		t.Errorf("expected 0 executions (skipped), got %d", len(mock.executedArgs))
	}
}

// authExecError returns an *ExecError that mimics the CLI returning the
// AMTAuthenticationFailed exit code.
func authExecError() error {
	return &ExecError{
		ExitCode: utils.AMTAuthenticationFailed.Code,
		Output:   "401 Unauthorized",
		Err:      fmt.Errorf("exit status %d", utils.AMTAuthenticationFailed.Code),
	}
}

// nonAuthExecError returns an *ExecError with a different (non-auth) exit code.
func nonAuthExecError() error {
	return &ExecError{
		ExitCode: 42,
		Output:   "something else blew up",
		Err:      fmt.Errorf("exit status 42"),
	}
}

func TestExecuteWithPasswordFallback_SkippedWhenPreProvisioning(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	mock := newMockExecutor()
	mock.errs = []error{authExecError()}
	po.executor = mock
	po.currentControlMode = 0 // pre-provisioning: rotation must not happen

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"})
	if err == nil {
		t.Fatalf("expected auth error to surface, got nil")
	}

	if mock.callCount != 1 {
		t.Errorf("expected 1 call (no rotation in pre-provisioning), got %d", mock.callCount)
	}
}

func TestExecuteWithPasswordFallback_NonExecErrorDoesNotRotate(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	mock := newMockExecutor()
	mock.errs = []error{fmt.Errorf("generic non-ExecError failure")}
	po.executor = mock
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"})
	if err == nil {
		t.Fatalf("expected error to surface, got nil")
	}

	if mock.callCount != 1 {
		t.Errorf("non-ExecError must not trigger rotation, got %d calls", mock.callCount)
	}
}

func TestExecuteWithPasswordFallback_NonAuthExitCodeDoesNotRotate(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	mock := newMockExecutor()
	mock.errs = []error{nonAuthExecError()}
	po.executor = mock
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"})
	if err == nil {
		t.Fatalf("expected error to surface, got nil")
	}

	if mock.callCount != 1 {
		t.Errorf("non-auth exit code must not trigger rotation, got %d calls", mock.callCount)
	}
}

func TestExecuteWithPasswordFallback_AuthExitCodeTriggersRotationAndRetry(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	mock := newMockExecutor()
	// Call 0: original command fails with auth error.
	// Call 1: non-interactive password rotation using currentPassword succeeds.
	// Call 2: original command retried successfully.
	mock.errs = []error{authExecError(), nil, nil}
	po.executor = mock
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"})
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v", err)
	}

	if mock.callCount != 3 {
		t.Fatalf("expected 3 calls (fail, rotate, retry), got %d", mock.callCount)
	}

	rotateArgs := strings.Join(mock.executedArgs[1], " ")
	if !strings.Contains(rotateArgs, "configure amtpassword --password old-pass --newamtpassword new-pass") {
		t.Errorf("expected non-interactive rotation command on call 2, got: %s", rotateArgs)
	}

	retryArgs := strings.Join(mock.executedArgs[2], " ")
	if !strings.Contains(retryArgs, "amtinfo") {
		t.Errorf("expected retry of original command on call 3, got: %s", retryArgs)
	}
}

func TestExecuteWithPasswordFallback_NoSettleRetryWhenNotActivatedThisRun(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	mock.errs = []error{nonAuthExecError()}
	po.executor = mock
	po.settleDelaySeconds = 0
	// activatedThisRun defaults to false: device was already activated, so a
	// configuration failure is genuine and must fail fast without settle retries.

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"})
	if err == nil {
		t.Fatalf("expected error to surface, got nil")
	}

	if mock.callCount != 1 {
		t.Errorf("expected 1 call (no settle retry when not activated this run), got %d", mock.callCount)
	}
}

func TestExecuteWithPasswordFallback_SettleRetryRecoversAfterActivation(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	// Two transient post-activation failures (dropped connection / locked
	// account), then success once the firmware settles.
	mock.errs = []error{nonAuthExecError(), nonAuthExecError(), nil}
	po.executor = mock
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"})
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v, want nil after settle retry", err)
	}

	if mock.callCount != 3 {
		t.Fatalf("expected 3 calls (fail, fail, succeed), got %d", mock.callCount)
	}
}

func TestExecuteWithPasswordFallback_SettleRetryBounded(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	// Every attempt fails; the retry loop must be bounded and then surface the error.
	mock.errs = []error{nonAuthExecError(), nonAuthExecError(), nonAuthExecError(), nonAuthExecError(), nonAuthExecError()}
	po.executor = mock
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"})
	if err == nil {
		t.Fatalf("expected error to surface after exhausting settle retries, got nil")
	}

	if mock.callCount != postActivationSettleAttempts {
		t.Errorf("expected %d calls (bounded settle retries), got %d", postActivationSettleAttempts, mock.callCount)
	}
}

func TestExecuteWithPasswordFallback_SettleRetrySkippedForDeviceNotActivated(t *testing.T) {
	cfg := config.Configuration{}

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	// A device-not-activated failure is not a settling symptom; do not retry.
	mock.errs = []error{deviceNotActivatedExecError()}
	po.executor = mock
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"})
	if err == nil {
		t.Fatalf("expected device-not-activated error to surface, got nil")
	}

	if mock.callCount != 1 {
		t.Errorf("expected 1 call (no settle retry for device-not-activated), got %d", mock.callCount)
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
// rotation runs once, on the initial execution. Routing settle retries back
// through executeWithPasswordRotation would re-prompt on every attempt and, on
// success, recurse into the settle loop again.
func TestExecuteWithPasswordFallback_SettleRetryDoesNotRePrompt(t *testing.T) {
	originalPR := utils.PR
	utils.PR = &failingPasswordReader{}

	defer func() { utils.PR = originalPR }()

	cfg := config.Configuration{}
	// An AdminPassword plus control mode 2 is what arms the rotation path.
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	// A supplied current password arms the non-interactive rotation attempt.
	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	mock := newMockExecutor()
	// Every call reports an auth failure — the error that triggers rotation. The
	// slice is longer than any path through the loop needs, so a rotating retry
	// path cannot pass by simply running out of errors.
	mock.errs = make([]error, 32)
	for i := range mock.errs {
		mock.errs[i] = authExecError()
	}

	po.executor = mock
	po.settleDelaySeconds = 0
	po.activatedThisRun = true
	po.currentControlMode = 2

	if err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"}); err == nil {
		t.Fatalf("expected error to surface after exhausting settle retries, got nil")
	}

	rotations := 0

	for _, args := range mock.executedArgs {
		if slices.Contains(args, commandAMTPassword) {
			rotations++
		}
	}

	// Exactly one: the initial execution's rotation. Routing the retries back
	// through executeWithPasswordRotation would rotate once per settle attempt.
	if rotations != 1 {
		t.Errorf("expected 1 rotation attempt (the initial one), got %d across %s",
			rotations, strings.Join(mock.executedArgs[len(mock.executedArgs)-1], " "))
	}
}

func TestExecuteMEBxConfiguration_RunsWhenAlreadyActivated(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.MEBXPassword = "mebx-pwd"
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock
	po.currentControlMode = 2 // already in ACM

	err := po.executeMEBxConfiguration()
	if err != nil {
		t.Fatalf("executeMEBxConfiguration() error = %v", err)
	}

	// Should have executed the MEBx configure command
	if len(mock.executedArgs) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(mock.executedArgs))
	}

	argsStr := strings.Join(mock.executedArgs[0], " ")
	if !strings.Contains(argsStr, "configure mebx --mebxpassword mebx-pwd") {
		t.Errorf("expected MEBx configure command, got: %s", argsStr)
	}
}

func deviceNotActivatedExecError() error {
	return &ExecError{
		ExitCode: utils.DeviceNotActivated.Code,
		Output:   "device is not activated to configure. Please activate the device first",
		Err:      fmt.Errorf("exit status %d", utils.DeviceNotActivated.Code),
	}
}

func TestVerifyAndAlignAMTPassword_SkipsWhenDeviceNotActivated_WithCurrentPassword(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	po.currentControlMode = 2

	mock := newMockExecutor()
	mock.errs = []error{deviceNotActivatedExecError()}
	po.executor = mock

	err := po.verifyAndAlignAMTPassword()
	if err != nil {
		t.Fatalf("verifyAndAlignAMTPassword() error = %v, want nil", err)
	}

	if mock.callCount != 1 {
		t.Fatalf("expected 1 call and graceful skip, got %d", mock.callCount)
	}
}

func TestVerifyAndAlignAMTPassword_SkipsWhenDeviceNotActivated_NoCurrentPassword(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "", "", false)
	po.currentControlMode = 0 // executeWithPasswordFallback returns original error in pre-provisioning

	mock := newMockExecutor()
	mock.errs = []error{deviceNotActivatedExecError()}
	po.executor = mock

	err := po.verifyAndAlignAMTPassword()
	if err != nil {
		t.Fatalf("verifyAndAlignAMTPassword() error = %v, want nil", err)
	}

	if mock.callCount != 1 {
		t.Fatalf("expected 1 call and graceful skip, got %d", mock.callCount)
	}
}
