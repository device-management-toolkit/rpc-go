/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package diagnostics

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	internaldiag "github.com/device-management-toolkit/rpc-go/v2/internal/commands/diagnostics"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errUnexpectedPrompt = errors.New("unexpected password prompt")
	errClassRead        = errors.New("class read failed")
)

// noPrompt fails every password prompt so a test can never block on stdin.
type noPrompt struct{}

func (noPrompt) ReadPassword() (string, error) { return "", errUnexpectedPrompt }

func (noPrompt) ReadPasswordWithConfirmation(_, _ string) (string, error) {
	return "", errUnexpectedPrompt
}

// amtReachable is set by TestMain when this process is elevated and HECI is
// present. A call that passes validation would then really read this device
// (and Bundle would write a file), so requireReachedAMT skips it.
var amtReachable bool

func TestMain(m *testing.M) {
	utils.PR = noPrompt{}
	amtReachable = utils.IsElevated() && !heciAbsent(probeControlMode())

	os.Exit(m.Run())
}

// probeControlMode reads the AMT control mode, a read-only HECI query, and
// closes the HECI connection again.
func probeControlMode() error {
	amtCommand := amt.NewAMTCommand()
	defer amtCommand.Close()

	_, err := amtCommand.GetControlMode()

	return err
}

// heciAbsent reports whether a probe error shows that the process cannot use
// a HECI device on this machine. Any other failure, such as a device another
// process holds, can clear while a test runs, so HECI counts as present.
func heciAbsent(probeErr error) bool {
	return errors.Is(probeErr, heci.ErrDeviceNotFound) ||
		errors.Is(probeErr, heci.ErrUnsupportedDevice) ||
		errors.Is(probeErr, heci.ErrPermissionDenied)
}

// requireReachedAMT runs call and asserts that validation passed and the call
// failed only on AMT access. When AMT is reachable it skips the test without
// running call, which would read this device.
func requireReachedAMT(t *testing.T, call func() error) {
	t.Helper()

	if amtReachable {
		t.Skip("skipped: this process is elevated and AMT is reachable over HECI, so the call would read this device")
	}

	err := call()
	if !failedOnAMTAccess(err) {
		t.Fatalf("expected validation to pass and AMT access to fail, got: %v", err)
	}
}

// failedOnAMTAccess reports whether err is one of the errors the command's
// AfterApply returns when it cannot use AMT: the process is not elevated, no
// HECI driver or device was found, or the MEI device has no AMT client
// (non-vPro hardware, where heciAbsent lets these tests run).
func failedOnAMTAccess(err error) bool {
	return errors.Is(err, utils.IncorrectPermissions) ||
		errors.Is(err, utils.HECIDriverNotDetected) ||
		errors.Is(err, utils.AmtNotDetected)
}

func TestHECIAbsent(t *testing.T) {
	tests := []struct {
		name     string
		probeErr error
		want     bool
	}{
		{"AMT answered", nil, false},
		{"device held by another process", fmt.Errorf("connect: %w", syscall.EBUSY), false},
		{"no MEI device or driver", fmt.Errorf("%w: %w", heci.ErrDeviceNotFound, fs.ErrNotExist), true},
		{"no AMT client on the MEI device", heci.ErrUnsupportedDevice, true},
		{"no access to the MEI device", heci.ErrPermissionDenied, true},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, heciAbsent(tt.probeErr))
		})
	}
}

func TestFailedOnAMTAccess(t *testing.T) {
	// The wrapped errors are the ones AfterApply builds from a failed HECI probe.
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"not elevated", utils.IncorrectPermissions, true},
		{"no access to the MEI device", fmt.Errorf("%w: %w", utils.IncorrectPermissions, heci.ErrPermissionDenied), true},
		{"no HECI on this architecture", utils.HECIDriverNotDetected, true},
		{"no MEI device or driver", fmt.Errorf("%w: %w", utils.HECIDriverNotDetected, heci.ErrDeviceNotFound), true},
		{"no AMT client on the MEI device", fmt.Errorf("%w: %w", utils.AmtNotDetected, heci.ErrUnsupportedDevice), true},
		{"call succeeded", nil, false},
		{"validation failed", errors.New("--all cannot be used with --class"), false},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, failedOnAMTAccess(tt.err))
		})
	}
}

func TestRequireReachedAMT_SkipsWithoutCallingWhenAMTIsReachable(t *testing.T) {
	reachable := amtReachable
	amtReachable = true

	t.Cleanup(func() { amtReachable = reachable })

	called := false

	var inner *testing.T

	t.Run("reach AMT", func(t *testing.T) {
		inner = t

		requireReachedAMT(t, func() error {
			called = true

			return nil
		})
	})

	assert.True(t, inner.Skipped())
	assert.False(t, called)
}

func TestValidOptionsReachAMT(t *testing.T) {
	bundleOutput := filepath.Join(t.TempDir(), "bundle.zip")

	tests := []struct {
		name string
		call func() error
	}{
		{"CIRA", func() error {
			_, err := CIRA(CIRAOptions{})

			return err
		}},
		{"CSME", func() error {
			_, err := CSME(CSMEOptions{})

			return err
		}},
		{"WSMAN all classes", func() error {
			_, err := WSMAN(WSMANOptions{All: true})

			return err
		}},
		{"WSMAN some classes as table", func() error {
			_, err := WSMAN(WSMANOptions{
				Classes: []string{"AMT_GeneralSettings", "CIM_Chassis"}, Format: "table",
				AMTPassword: "P@ssw0rd", SkipAMTCertCheck: true,
			})

			return err
		}},
		{"Bundle", func() error {
			_, err := Bundle(BundleOptions{Output: bundleOutput, AMTPassword: "P@ssw0rd"})

			return err
		}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			requireReachedAMT(t, tt.call)
		})
	}

	assert.NoFileExists(t, bundleOutput, "Bundle wrote a file without reaching AMT")
}

func TestWSMAN_RejectsInvalidOptionsBeforeAMTAccess(t *testing.T) {
	tests := []struct {
		name    string
		opts    WSMANOptions
		wantErr string
	}{
		{"neither All nor Classes", WSMANOptions{}, "specify --all or at least one --class"},
		{"All and Classes", WSMANOptions{All: true, Classes: []string{"CIM_Chassis"}}, "--all cannot be used with --class"},
		{"unknown class", WSMANOptions{Classes: []string{"CIM_Chassis", "Bogus_Class"}}, "unsupported WSMAN class: Bogus_Class"},
		{"only blank classes", WSMANOptions{Classes: []string{" "}}, "at least one valid --class must be provided"},
		{"unknown format", WSMANOptions{All: true, Format: "yaml"}, `--format must be one of "json","xml","table" but got "yaml"`},
		{"format in upper case", WSMANOptions{All: true, Format: "JSON"}, `--format must be one of "json","xml","table" but got "JSON"`},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			result, err := WSMAN(tt.opts)

			require.EqualError(t, err, tt.wantErr)
			assert.False(t, failedOnAMTAccess(err))
			assert.Nil(t, result)
		})
	}
}

func TestNewWSMANCommand_MapsEveryOption(t *testing.T) {
	cmd, ctx := newWSMANCommand(WSMANOptions{
		Classes:          []string{"AMT_GeneralSettings", "CIM_Chassis"},
		All:              false,
		Format:           "xml",
		AMTPassword:      "P@ssw0rd",
		SkipAMTCertCheck: true,
	})

	assert.Equal(t, &internaldiag.WSManGetCmd{
		Class:  []string{"AMT_GeneralSettings", "CIM_Chassis"},
		Format: "xml",
	}, cmd)
	assert.Equal(t, &commands.Context{AMTPassword: "P@ssw0rd", SkipAMTCertCheck: true}, ctx)
}

func TestNewWSMANCommand_AppliesTheCLIDefaultFormat(t *testing.T) {
	cmd, ctx := newWSMANCommand(WSMANOptions{All: true})

	assert.Equal(t, &internaldiag.WSManGetCmd{All: true, Format: "json"}, cmd)
	assert.Equal(t, &commands.Context{}, ctx)
}

func TestNewBundleCommand_MapsEveryOption(t *testing.T) {
	cmd, ctx := newBundleCommand(BundleOptions{
		Output:           "out/bundle.zip",
		AMTPassword:      "P@ssw0rd",
		SkipAMTCertCheck: true,
	})

	assert.Equal(t, &internaldiag.BundleCmd{Output: "out/bundle.zip"}, cmd)
	assert.Equal(t, &commands.Context{AMTPassword: "P@ssw0rd", SkipAMTCertCheck: true}, ctx)
}

func TestNewCommands_EmptyOptionsMapToBareCommands(t *testing.T) {
	ciraCmd, ciraCtx := newCIRACommand(CIRAOptions{})
	assert.Equal(t, &internaldiag.CIRACmd{}, ciraCmd)
	assert.Equal(t, &commands.Context{}, ciraCtx)

	csmeCmd, csmeCtx := newCSMECommand(CSMEOptions{})
	assert.Equal(t, &internaldiag.CSMECmd{}, csmeCmd)
	assert.Equal(t, &commands.Context{}, csmeCtx)
}

func TestWSMANClasses_ListsWhatWSMANListPrints(t *testing.T) {
	classes := WSMANClasses(WSMANClassesOptions{})

	assert.Equal(t, internaldiag.SupportedWSMANClasses(), classes)
	assert.IsIncreasing(t, classes)
	assert.Contains(t, classes, "AMT_GeneralSettings")
	assert.Contains(t, classes, "IPS_SecIOService")

	// The caller owns the returned slice.
	classes[0] = "changed"

	assert.NotEqual(t, "changed", WSMANClasses(WSMANClassesOptions{})[0])
}

func TestNewWSMANResult(t *testing.T) {
	classes := []WSMANClass{
		{Class: "AMT_GeneralSettings", Data: map[string]string{"HostName": "device"}},
		{Class: "CIM_Chassis", Err: errClassRead},
	}

	tests := []struct {
		name       string
		classes    []WSMANClass
		fetchErr   error
		format     string
		wantResult bool
		wantErr    string
		wantIs     error
	}{
		{"every class read", classes[:1], nil, "json", true, "", nil},
		{"a class failed", classes, errClassRead, "json", true, "WSMAN class fetch failed: class read failed", ErrClassFetchFailed},
		{"no class read", nil, errUnexpectedPrompt, "json", false, "unexpected password prompt", errUnexpectedPrompt},
		{"render failed", classes[:1], nil, "yaml", true, "unsupported format: yaml", nil},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			result, err := newWSMANResult(tt.classes, tt.fetchErr, tt.format)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tt.wantErr)
			}

			if tt.wantIs != nil {
				require.ErrorIs(t, err, tt.wantIs)
			}

			if !tt.wantResult {
				assert.Nil(t, result)

				return
			}

			require.NotNil(t, result)
			assert.Equal(t, tt.classes, result.Classes)

			if tt.format == "json" {
				want, renderErr := internaldiag.RenderWSMANClasses(tt.classes, "json")
				require.NoError(t, renderErr)
				assert.Equal(t, want, result.Output)
			}
		})
	}
}

func TestBundleError(t *testing.T) {
	complete := &BundleResult{Path: "bundle.zip", Manifest: BundleManifest{
		CreatedAt:  time.Unix(0, 0),
		Collectors: []BundleCollector{{Name: "cira", File: "cira.txt", Status: "success"}},
	}}
	incomplete := &BundleResult{Path: "bundle.zip", Manifest: BundleManifest{Collectors: []BundleCollector{
		{Name: "cira", File: "cira.txt", Status: "success"},
		{Name: "csme", Status: "failed", Error: "not supported"},
		{Name: "wsman", File: "wsman.json", Status: "partial", Error: "1 of 52 WSMAN classes failed to retrieve"},
	}}}
	nothingCollected := errors.New("no diagnostics were collected (manifest written to bundle.zip): cira: failed")

	tests := []struct {
		name    string
		result  *BundleResult
		err     error
		wantErr string
		wantIs  []error
	}{
		{"complete", complete, nil, "", nil},
		{"incomplete", incomplete, nil, "diagnostics bundle incomplete: 2 diagnostic collector(s) were incomplete; see manifest.json for details", []error{ErrBundleIncomplete}},
		{"nothing collected", incomplete, nothingCollected, "diagnostics bundle incomplete: " + nothingCollected.Error(), []error{ErrBundleIncomplete, nothingCollected}},
		{"no bundle written", nil, utils.IncorrectPermissions, utils.IncorrectPermissions.Error(), []error{utils.IncorrectPermissions}},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			err := bundleError(tt.result, tt.err)

			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.EqualError(t, err, tt.wantErr)

			for _, target := range tt.wantIs {
				require.ErrorIs(t, err, target)
			}

			if tt.result == nil {
				assert.NotErrorIs(t, err, ErrBundleIncomplete)
			}
		})
	}
}

func TestNewCIRAResult_CarriesTheCLIText(t *testing.T) {
	var log CIRALog

	want, err := internaldiag.CIRALogText(log)
	require.NoError(t, err)
	require.NotEmpty(t, want)

	result, err := newCIRAResult(log)
	require.NoError(t, err)
	assert.Equal(t, log, result.Log)
	assert.Equal(t, want, result.Text)
}

func TestErrCIRALogNotSupported_IsTheCommandsError(t *testing.T) {
	assert.Equal(t, internaldiag.ErrCIRALogNotSupported, ErrCIRALogNotSupported)
}
