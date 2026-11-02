/*********************************************************************
 * Copyright (c) Intel Corporation 2025
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/config"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFailureCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantOK   bool
	}{
		{name: "nil", err: nil, wantCode: 0, wantOK: false},
		{name: "exec error", err: &ExecError{ExitCode: 100, Err: errors.New("exit status 100")}, wantCode: 100, wantOK: true},
		{name: "custom error", err: utils.AMTAuthenticationFailed, wantCode: utils.AMTAuthenticationFailed.Code, wantOK: true},
		{name: "wrapped custom error", err: fmt.Errorf("x: %w", utils.DeviceNotActivated), wantCode: utils.DeviceNotActivated.Code, wantOK: true},
		{name: "plain error", err: errors.New("boom"), wantCode: 0, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, ok := failureCode(tt.err)
			require.Equal(t, tt.wantCode, code)
			require.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestHideStepCode(t *testing.T) {
	require.NoError(t, hideStepCode(nil))

	tests := []struct {
		name string
		err  error
	}{
		{name: "custom error", err: utils.AMTAuthenticationFailed},
		{name: "wrapped exec error", err: fmt.Errorf("step: %w", authExecError())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hidden := hideStepCode(tt.err)
			require.Error(t, hidden)
			require.Equal(t, tt.err.Error(), hidden.Error())

			var customErr utils.CustomError
			require.False(t, errors.As(hidden, &customErr), "CustomError must not be reachable")

			var execErr *ExecError
			require.False(t, errors.As(hidden, &execErr), "*ExecError must not be reachable")

			_, ok := failureCode(hidden)
			require.False(t, ok)
		})
	}
}

func TestHideStepCode_KeepsCIRASentinel(t *testing.T) {
	err := fmt.Errorf("%w: %w", ErrCIRAConfiguration, hideStepCode(utils.AMTAuthenticationFailed))

	require.ErrorIs(t, err, ErrCIRAConfiguration)

	var customErr utils.CustomError
	require.False(t, errors.As(err, &customErr))
	require.Equal(t, ErrCIRAConfiguration.Error()+": "+utils.AMTAuthenticationFailed.Error(), err.Error())
}

func TestRotation_InProcessAuthFailureRotates(t *testing.T) {
	rotations := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", true)
	mock := newMockExecutor()
	po.executor = mock
	po.currentControlMode = 1
	po.globalPassword = "stale-pass"

	var got []string

	step := func(amtPassword string) error {
		got = append(got, amtPassword)
		if len(got) == 1 {
			return utils.AMTAuthenticationFailed
		}

		return nil
	}

	require.NoError(t, po.executeWithPasswordFallback(step))

	require.Equal(t, []string{"stale-pass", "new-pass"}, got)
	require.Equal(t, "new-pass", po.globalPassword)

	// The rotation runs in-process; nothing reaches the executor.
	require.Equal(t, 0, mock.callCount)
	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "new-pass", true)}, *rotations)
}

func TestSettle_InProcessDeviceNotActivatedNotRetried(t *testing.T) {
	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)
	mock := newMockExecutor()
	po.executor = mock
	po.settleDelaySeconds = 0
	po.activatedThisRun = true

	calls := 0
	step := func(string) error {
		calls++

		return fmt.Errorf("x: %w", utils.DeviceNotActivated)
	}

	err := po.executeWithPasswordFallback(step)
	require.ErrorIs(t, err, utils.DeviceNotActivated)
	require.Equal(t, 1, calls)
	require.Equal(t, 0, mock.callCount)
}

func TestExecStep_PasswordFromArgumentOverridesStaleEnv(t *testing.T) {
	po := NewProfileOrchestrator(config.Configuration{}, "", "", false)
	mock := newMockExecutor()
	po.executor = mock

	extra := map[string]string{envAMTPassword: "stale", envMPSPassword: "mps"}
	step := po.execStep([]string{"rpc", "amtinfo"}, extra)

	require.NoError(t, step("fresh"))
	require.NoError(t, step(""))

	require.Equal(t, map[string]string{envAMTPassword: "fresh", envMPSPassword: "mps"}, mock.executedEnv[0])
	require.Equal(t, map[string]string{envMPSPassword: "mps"}, mock.executedEnv[1])
	// The caller's map is not mutated.
	require.Equal(t, map[string]string{envAMTPassword: "stale", envMPSPassword: "mps"}, extra)
}

func TestSettle_RetryUsesCurrentPassword(t *testing.T) {
	rotations := stubChangeAMTPassword(t)

	cfg := config.Configuration{}
	cfg.Configuration.AMTSpecific.AdminPassword = "new-pass"

	po := NewProfileOrchestrator(cfg, "old-pass", "", false)
	executor := newMockExecutor()
	po.executor = executor
	po.currentControlMode = 1
	po.activatedThisRun = true
	po.settleDelaySeconds = 0
	po.globalPassword = "stale-pass"

	var got []string

	step := func(amtPassword string) error {
		got = append(got, amtPassword)

		switch len(got) {
		case 1:
			return utils.AMTAuthenticationFailed
		case 2:
			return errors.New("connection reset while AMT settles")
		default:
			return nil
		}
	}

	require.NoError(t, po.executeWithPasswordFallback(step))

	// Initial call with the stale password, the post-rotation call, then the
	// settle retry: both later calls must see the rotated password.
	require.Equal(t, []string{"stale-pass", "new-pass", "new-pass"}, got)
	require.Equal(t, 0, executor.callCount, "nothing reaches the executor")
	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "new-pass", false)}, *rotations)
}

// stepFailingExecutor fails only the command whose arguments contain token.
type stepFailingExecutor struct {
	token        string
	err          error
	executedArgs [][]string
}

func (e *stepFailingExecutor) Execute(args []string, _ map[string]string) error {
	e.executedArgs = append(e.executedArgs, slices.Clone(args))

	if slices.Contains(args, e.token) {
		return e.err
	}

	return nil
}

// TestExecuteProfile_HidesStepCodes pins that ExecuteProfile hides every
// step's failure code, so a failed profile run exits with the generic code.
// Rows that reach the configuration steps pay the 1s initial utils.Pause
// (no seam); activation and password verification fail before it. Rows with
// inProcess set fail through the stubbed pkg call their token names instead
// of the executor.
func TestExecuteProfile_HidesStepCodes(t *testing.T) {
	stepErr := func(details string) error {
		return utils.CustomError{Code: utils.WSMANMessageError.Code, Message: utils.WSMANMessageError.Message, Details: details}
	}

	tests := []struct {
		name        string
		controlMode int
		profile     func(*config.Configuration)
		token       string
		inProcess   bool
		err         error
		wantCIRA    bool
	}{
		{
			name:        "activation",
			controlMode: 0,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.ControlMode = "ccmactivate"
			},
			token: "activate",
			err:   stepErr("activation step"),
		},
		{
			name:        "ACM upgrade",
			controlMode: 1,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.ControlMode = ACMMODE
			},
			token: "activate",
			err:   stepErr("upgrade step"),
		},
		{
			name:        "password verification",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.AdminPassword = "P@ssw0rd"
			},
			token:     "amtpassword",
			inProcess: true,
			err:       stepErr("password step"),
		},
		{
			name:        "MEBx",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.ControlMode = ACMMODE
				c.Configuration.AMTSpecific.MEBXPassword = "mebx-pass"
			},
			token:     "mebx",
			inProcess: true,
			err:       stepErr("mebx step"),
		},
		{
			name:        "AMT features",
			controlMode: 2,
			token:       "amtfeatures",
			inProcess:   true,
			err:         stepErr("amtfeatures step"),
		},
		{
			name:        "wired",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.Network.Wired.DHCPEnabled = true
			},
			token: "wired",
			err:   &ExecError{ExitCode: utils.NetworkConfigurationFailed.Code, Err: errors.New("wired step exit status 103")},
		},
		{
			name:        "wifisync",
			controlMode: 2,
			token:       "wifisync",
			err:         stepErr("wifisync step"),
		},
		{
			name:        "wireless",
			controlMode: 2,
			token:       "wireless",
			err:         stepErr("wireless step"),
		},
		{
			name:        "TLS",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.TLS.Enabled = true
			},
			token: "tls",
			err:   stepErr("tls step"),
		},
		{
			name:        "CIRA",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.AMTSpecific.CIRA.MPSAddress = "mps.example.com"
				c.Configuration.AMTSpecific.CIRA.MPSCert = "cert"
			},
			token:    "cira",
			err:      stepErr("cira step"),
			wantCIRA: true,
		},
		{
			name:        "proxy",
			controlMode: 2,
			profile: func(c *config.Configuration) {
				c.Configuration.Network.Proxies = []config.Proxy{{Address: "proxy.example.com", Port: 8080}}
			},
			token: "proxy",
			err:   stepErr("proxy step"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAMT := mock.NewMockInterface(ctrl)
			mockAMT.EXPECT().Initialize().Return(nil)
			mockAMT.EXPECT().GetControlMode().Return(tt.controlMode, nil)
			mockAMT.EXPECT().Close().Return(nil).AnyTimes()

			orig := newAMTCommand
			newAMTCommand = func() amt.Interface { return mockAMT }

			t.Cleanup(func() { newAMTCommand = orig })

			cfg := config.Configuration{}
			if tt.profile != nil {
				tt.profile(&cfg)
			}

			// Every row stubs every in-process call so none can reach AMT; an
			// in-process row's token names the call that fails.
			inProcessErrs := map[string]error{}
			if tt.inProcess {
				inProcessErrs[tt.token] = tt.err
			}

			passwordChanges := stubChangeAMTPassword(t, inProcessErrs["amtpassword"])
			mebxCalls := stubSetMEBx(t, inProcessErrs["mebx"])
			amtFeaturesCalls := stubSetAMTFeatures(t, inProcessErrs["amtfeatures"])

			po := NewProfileOrchestrator(cfg, "", "", false)
			po.settleDelaySeconds = 0
			exec := &stepFailingExecutor{token: tt.token, err: tt.err}
			po.SetExecutor(exec)

			err := po.ExecuteProfile()
			require.Error(t, err)

			failed := slices.ContainsFunc(exec.executedArgs, func(args []string) bool {
				return slices.Contains(args, tt.token)
			})
			if tt.inProcess {
				failed = map[string]bool{
					"amtpassword": len(*passwordChanges) > 0,
					"mebx":        len(*mebxCalls) > 0,
					"amtfeatures": len(*amtFeaturesCalls) > 0,
				}[tt.token]
			}

			require.True(t, failed, "the %s step must run", tt.name)

			var customErr utils.CustomError
			require.False(t, errors.As(err, &customErr), "CustomError must not be reachable: %v", err)

			var execErr *ExecError
			require.False(t, errors.As(err, &execErr), "*ExecError must not be reachable: %v", err)

			require.Contains(t, err.Error(), tt.err.Error())

			if tt.wantCIRA {
				require.ErrorIs(t, err, ErrCIRAConfiguration)
			}
		})
	}
}
