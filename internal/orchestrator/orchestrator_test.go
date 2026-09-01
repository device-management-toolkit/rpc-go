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
	executedEnv  []map[string]string // tracks env vars passed to Execute
	errOnCall    int                 // return error on this call index (-1 = never)
	// errs, if non-empty, overrides errOnCall and returns errs[i] for the i-th call
	// (falling back to nil once exhausted).
	errs      []error
	callCount int
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{errOnCall: -1}
}

func (m *mockExecutor) Execute(args []string, env map[string]string) error {
	// Copy args to avoid mutation issues
	argsCopy := make([]string, len(args))
	copy(argsCopy, args)
	m.executedArgs = append(m.executedArgs, argsCopy)

	// Copy env to avoid mutation issues
	envCopy := make(map[string]string)
	for k, v := range env {
		envCopy[k] = v
	}

	m.executedEnv = append(m.executedEnv, envCopy)

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

	// Verify credentials are NOT in command args (should be in environment variables)
	if strings.Contains(argsStr, "cert-pwd") || strings.Contains(argsStr, "--provisioningCertPwd") {
		t.Errorf("Provisioning cert password should not appear in command args (should use env var), got: %s", argsStr)
	}

	if strings.Contains(argsStr, "profile-mebx") || strings.Contains(argsStr, "--mebxpassword") {
		t.Errorf("MEBx password should not appear in command args (should use env var), got: %s", argsStr)
	}

	// Verify provisioning certificate material is NOT in command args
	if strings.Contains(argsStr, "cert-data") {
		t.Errorf("PROVISIONING_CERT should not appear in command args (should use env var), got: %s", argsStr)
	}

	// Verify passwords ARE in environment variables
	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["PROVISIONING_CERT_PASSWORD"] != "cert-pwd" {
		t.Errorf("expected PROVISIONING_CERT_PASSWORD=cert-pwd in env, got: %v", env)
	}

	if env["PROVISIONING_CERT"] != "cert-data" {
		t.Errorf("expected PROVISIONING_CERT=cert-data in env, got: %v", env)
	}

	if env["MEBX_PASSWORD"] != "profile-mebx" {
		t.Errorf("expected MEBX_PASSWORD=profile-mebx in env, got: %v", env)
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

	// Verify credentials are NOT in command args (should be in environment variables)
	if strings.Contains(argsStr, "cert-pwd") || strings.Contains(argsStr, "--provisioningCertPwd") {
		t.Errorf("Provisioning cert password should not appear in command args (should use env var), got: %s", argsStr)
	}

	if strings.Contains(argsStr, "cli-mebx") || strings.Contains(argsStr, "--mebxpassword") {
		t.Errorf("MEBx password should not appear in command args (should use env var), got: %s", argsStr)
	}

	// Verify passwords ARE in environment variables
	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["PROVISIONING_CERT_PASSWORD"] != "cert-pwd" {
		t.Errorf("expected PROVISIONING_CERT_PASSWORD=cert-pwd in env, got: %v", env)
	}

	if env["MEBX_PASSWORD"] != "cli-mebx" {
		t.Errorf("expected MEBX_PASSWORD=cli-mebx in env, got: %v", env)
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

	// Verify provisioning cert password is NOT in command args
	if strings.Contains(argsStr, "cert-pwd") || strings.Contains(argsStr, "--provisioningCertPwd") {
		t.Errorf("Provisioning cert password should not appear in command args (should use env var), got: %s", argsStr)
	}

	if strings.Contains(argsStr, "--mebxpassword") {
		t.Errorf("--mebxpassword should not be present when empty, got: %s", argsStr)
	}

	// Verify environment variables
	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["PROVISIONING_CERT_PASSWORD"] != "cert-pwd" {
		t.Errorf("expected PROVISIONING_CERT_PASSWORD=cert-pwd in env, got: %v", env)
	}

	if _, exists := env["MEBX_PASSWORD"]; exists {
		t.Errorf("MEBX_PASSWORD should not be in env when not provided, got: %v", env)
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

	// Verify MEBX_PASSWORD is NOT in environment variables for CCM mode
	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if _, exists := env["MEBX_PASSWORD"]; exists {
		t.Errorf("MEBX_PASSWORD should not be in env for CCM mode, got: %v", env)
	}
}

func TestExecuteACMUpgrade_PassesPasswordsViaEnv(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ProvisioningCert = "cert-data"
	cfg.Configuration.AMTSpecific.ProvisioningCertPwd = "cert-pwd"
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pwd"

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeACMUpgrade()
	if err != nil {
		t.Fatalf("executeACMUpgrade() error = %v", err)
	}

	if len(mock.executedArgs) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(mock.executedArgs))
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	// Verify provisioning cert password is NOT in command args
	if strings.Contains(argsStr, "cert-pwd") || strings.Contains(argsStr, "--provisioningCertPwd") {
		t.Errorf("Provisioning cert password should not appear in command args (should use env var), got: %s", argsStr)
	}

	// Verify provisioning certificate material is NOT in command args
	if strings.Contains(argsStr, "cert-data") {
		t.Errorf("PROVISIONING_CERT should not appear in command args (should use env var), got: %s", argsStr)
	}

	// Verify passwords ARE in environment variables
	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["PROVISIONING_CERT_PASSWORD"] != "cert-pwd" {
		t.Errorf("expected PROVISIONING_CERT_PASSWORD=cert-pwd in env, got: %v", env)
	}

	if env["PROVISIONING_CERT"] != "cert-data" {
		t.Errorf("expected PROVISIONING_CERT=cert-data in env, got: %v", env)
	}

	if env["AMT_PASSWORD"] != "admin-pwd" {
		t.Errorf("expected AMT_PASSWORD=admin-pwd in env, got: %v", env)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"}, nil)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"}, nil)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"}, nil)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"}, nil)
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v", err)
	}

	if mock.callCount != 3 {
		t.Fatalf("expected 3 calls (fail, rotate, retry), got %d", mock.callCount)
	}

	rotateArgs := strings.Join(mock.executedArgs[1], " ")
	if !strings.Contains(rotateArgs, "configure amtpassword") {
		t.Errorf("expected non-interactive rotation command on call 2, got: %s", rotateArgs)
	}
	// Verify passwords are NOT in the command args (they should be in environment variables)
	if strings.Contains(rotateArgs, "old-pass") || strings.Contains(rotateArgs, "new-pass") {
		t.Errorf("passwords should not appear in command args (should use env vars), got: %s", rotateArgs)
	}

	// Verify passwords ARE in environment variables for rotation command (call 1)
	rotateEnv := mock.executedEnv[1]
	if rotateEnv["AMT_PASSWORD"] != "old-pass" {
		t.Errorf("expected AMT_PASSWORD=old-pass in rotation env, got: %v", rotateEnv)
	}

	if rotateEnv["NEW_AMT_PASSWORD"] != "new-pass" {
		t.Errorf("expected NEW_AMT_PASSWORD=new-pass in rotation env, got: %v", rotateEnv)
	}

	retryArgs := strings.Join(mock.executedArgs[2], " ")
	if !strings.Contains(retryArgs, "amtinfo") {
		t.Errorf("expected retry of original command on call 3, got: %s", retryArgs)
	}

	// Verify retry command (call 2) has the new password in env
	retryEnv := mock.executedEnv[2]
	if retryEnv["AMT_PASSWORD"] != "new-pass" {
		t.Errorf("expected AMT_PASSWORD=new-pass in retry env, got: %v", retryEnv)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"}, nil)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"}, nil)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"}, nil)
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

	err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"}, nil)
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

	if err := po.executeWithPasswordFallback([]string{"rpc", "configure", "wifisync"}, nil); err == nil {
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
	if !strings.Contains(argsStr, "configure mebx") {
		t.Errorf("expected MEBx configure command, got: %s", argsStr)
	}
	// Verify MEBx password is NOT in the command args (should be in environment variable)
	if strings.Contains(argsStr, "mebx-pwd") {
		t.Errorf("MEBx password should not appear in command args (should use env var), got: %s", argsStr)
	}

	// Verify MEBx password IS in environment variables
	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["MEBX_PASSWORD"] != "mebx-pwd" {
		t.Errorf("expected MEBX_PASSWORD=mebx-pwd in env, got: %v", env)
	}
}

func TestExecuteWithEnv_PassesEnvironmentVariables(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "test-pass"

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock
	po.currentControlMode = 2

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"}, nil)
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v", err)
	}

	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["AMT_PASSWORD"] != "test-pass" {
		t.Errorf("expected AMT_PASSWORD=test-pass in env, got: %v", env)
	}
}

func TestExecuteActivation_PassesAllPasswordsViaEnv(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.ControlMode = ACMMODE
	cfg.Configuration.AMTSpecific.ProvisioningCert = "cert-data"
	cfg.Configuration.AMTSpecific.ProvisioningCertPwd = "cert-pwd"
	cfg.Configuration.AMTSpecific.MEBXPassword = "mebx-pwd"
	cfg.Configuration.AMTSpecific.AdminPassword = "admin-pwd"

	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeActivation()
	if err != nil {
		t.Fatalf("executeActivation() error = %v", err)
	}

	if len(mock.executedEnv) != 1 {
		t.Fatalf("expected 1 execution with env, got %d", len(mock.executedEnv))
	}

	env := mock.executedEnv[0]
	if env["PROVISIONING_CERT_PASSWORD"] != "cert-pwd" {
		t.Errorf("expected PROVISIONING_CERT_PASSWORD=cert-pwd in env, got: %v", env)
	}

	if env["MEBX_PASSWORD"] != "mebx-pwd" {
		t.Errorf("expected MEBX_PASSWORD=mebx-pwd in env, got: %v", env)
	}

	if env["AMT_PASSWORD"] != "admin-pwd" {
		t.Errorf("expected AMT_PASSWORD=admin-pwd in env, got: %v", env)
	}
}

func TestPasswordRotation_PassesPasswordsViaEnv(t *testing.T) {
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

	err := po.executeWithPasswordFallback([]string{"rpc", "amtinfo"}, nil)
	if err != nil {
		t.Fatalf("executeWithPasswordFallback() error = %v", err)
	}

	if mock.callCount != 3 {
		t.Fatalf("expected 3 calls, got %d", mock.callCount)
	}

	// Verify rotation command (call 1) has both old and new passwords in env
	rotateEnv := mock.executedEnv[1]
	if rotateEnv["AMT_PASSWORD"] != "old-pass" {
		t.Errorf("expected AMT_PASSWORD=old-pass in rotation env, got: %v", rotateEnv)
	}

	if rotateEnv["NEW_AMT_PASSWORD"] != "new-pass" {
		t.Errorf("expected NEW_AMT_PASSWORD=new-pass in rotation env, got: %v", rotateEnv)
	}

	// Verify retry command (call 2) has the new password in env
	retryEnv := mock.executedEnv[2]
	if retryEnv["AMT_PASSWORD"] != "new-pass" {
		t.Errorf("expected AMT_PASSWORD=new-pass in retry env, got: %v", retryEnv)
	}
}

func TestVerifyAndAlignAMTPassword_UpdatesGlobalPasswordOnSuccess(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-profile-pass"

	po := NewProfileOrchestrator(cfg, "current-pass", "", false)
	mock := newMockExecutor()
	po.executor = mock
	po.currentControlMode = 2

	// Verify initial state
	if po.globalPassword != "new-profile-pass" {
		t.Errorf("initial globalPassword = %q, want %q", po.globalPassword, "new-profile-pass")
	}

	err := po.verifyAndAlignAMTPassword()
	if err != nil {
		t.Fatalf("verifyAndAlignAMTPassword() error = %v", err)
	}

	// Verify password rotation was attempted with current password
	if mock.callCount != 1 {
		t.Fatalf("expected 1 call (non-interactive rotation), got %d", mock.callCount)
	}

	rotateArgs := strings.Join(mock.executedArgs[0], " ")
	if !strings.Contains(rotateArgs, "configure amtpassword") {
		t.Errorf("expected password rotation command, got: %s", rotateArgs)
	}

	// Verify rotation used correct passwords in env
	rotateEnv := mock.executedEnv[0]
	if rotateEnv["AMT_PASSWORD"] != "current-pass" {
		t.Errorf("expected AMT_PASSWORD=current-pass in rotation env, got: %v", rotateEnv)
	}

	if rotateEnv["NEW_AMT_PASSWORD"] != "new-profile-pass" {
		t.Errorf("expected NEW_AMT_PASSWORD=new-profile-pass in rotation env, got: %v", rotateEnv)
	}

	// Verify globalPassword was updated after successful rotation
	if po.globalPassword != "new-profile-pass" {
		t.Errorf("globalPassword after rotation = %q, want %q", po.globalPassword, "new-profile-pass")
	}
}

func TestVerifyAndAlignAMTPassword_IdempotentProbe(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "profile-pass"

	// No currentPassword provided, so we skip direct rotation and go to idempotent probe
	po := NewProfileOrchestrator(cfg, "", "", false)
	mock := newMockExecutor()
	po.executor = mock
	po.currentControlMode = 2

	err := po.verifyAndAlignAMTPassword()
	if err != nil {
		t.Fatalf("verifyAndAlignAMTPassword() error = %v", err)
	}

	// Verify idempotent probe was executed
	if mock.callCount != 1 {
		t.Fatalf("expected 1 call (idempotent probe), got %d", mock.callCount)
	}

	probeArgs := strings.Join(mock.executedArgs[0], " ")
	if !strings.Contains(probeArgs, "configure amtpassword") {
		t.Errorf("expected password change command, got: %s", probeArgs)
	}

	// Verify probe used current globalPassword as AMT_PASSWORD
	probeEnv := mock.executedEnv[0]
	if probeEnv["AMT_PASSWORD"] != "profile-pass" {
		t.Errorf("expected AMT_PASSWORD=profile-pass in probe env, got: %v", probeEnv)
	}

	if probeEnv["NEW_AMT_PASSWORD"] != "profile-pass" {
		t.Errorf("expected NEW_AMT_PASSWORD=profile-pass in probe env, got: %v", probeEnv)
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

func TestExecuteCIRAConfiguration_SkipsWhenNotConfigured(t *testing.T) {
	po := NewProfileOrchestrator(config.Configuration{}, "pwd", "", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeCIRAConfiguration()
	if err != nil {
		t.Fatalf("executeCIRAConfiguration() error = %v, want nil", err)
	}

	if mock.callCount != 0 {
		t.Errorf("expected no executor calls when CIRA is not configured, got %d", mock.callCount)
	}
}

func TestExecuteCIRAConfiguration_UsesCorrectFlagNames(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.CIRA.MPSAddress = "mps.example.com"
	cfg.Configuration.AMTSpecific.CIRA.MPSCert = "cert-pem-data"
	cfg.Configuration.AMTSpecific.CIRA.MPSPassword = "mps-secret"

	po := NewProfileOrchestrator(cfg, "amt-pwd", "", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeCIRAConfiguration()
	if err != nil {
		t.Fatalf("executeCIRAConfiguration() error = %v", err)
	}

	if mock.callCount != 1 {
		t.Fatalf("expected 1 executor call, got %d", mock.callCount)
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	// Regression guard: orchestrator must use --mpsaddress / --mpscert, not dashed variants.
	for _, wrong := range []string{"--mps-address", "--mps-cert"} {
		if slices.Contains(args, wrong) {
			t.Errorf("args must not contain %q (kebab-case), got: %s", wrong, argsStr)
		}
	}

	for _, want := range []string{"configure", "cira", "--mpsaddress", "mps.example.com", "--mpscert", "cert-pem-data"} {
		if !slices.Contains(args, want) {
			t.Errorf("expected %q in args, got: %s", want, argsStr)
		}
	}

	// MPS password must be passed via env var, not as a CLI arg (credential leak prevention).
	for _, leaked := range []string{"--mpspassword", "mps-secret"} {
		if slices.Contains(args, leaked) {
			t.Errorf("MPS password must not appear in args, got: %s", argsStr)
		}
	}

	env := mock.executedEnv[0]
	if env["MPS_PASSWORD"] != "mps-secret" {
		t.Errorf("expected MPS_PASSWORD env var to be %q, got: %q", "mps-secret", env["MPS_PASSWORD"])
	}
}

func TestExecuteCIRAConfiguration_WithEnvDetection(t *testing.T) {
	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.CIRA.MPSAddress = "mps.example.com"
	cfg.Configuration.AMTSpecific.CIRA.MPSCert = "cert-pem-data"
	cfg.Configuration.AMTSpecific.CIRA.EnvironmentDetection = []string{"corp.example.com", "vpn.example.com"}

	po := NewProfileOrchestrator(cfg, "amt-pwd", "", false)
	mock := newMockExecutor()
	po.executor = mock

	err := po.executeCIRAConfiguration()
	if err != nil {
		t.Fatalf("executeCIRAConfiguration() error = %v", err)
	}

	args := mock.executedArgs[0]
	argsStr := strings.Join(args, " ")

	if !strings.Contains(argsStr, "--envdetection corp.example.com,vpn.example.com") {
		t.Errorf("expected --envdetection with comma-joined values, got: %s", argsStr)
	}
}
