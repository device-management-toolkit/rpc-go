/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package orchestrator

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/configure"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/require"
)

// wsmanPostErr builds the error go-wsman-messages returns for an HTTP status
// >= 401, the way the library builds it (pkg/wsman/client/wsman.go).
func wsmanPostErr(status string) error {
	errPostResponse := errors.New("wsman.Client post received")

	return fmt.Errorf("%w: %v\n%v", errPostResponse, status, "<html>body</html>")
}

func TestIsAMTUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"go-wsman 401 wrapped by a step", fmt.Errorf("failed to configure ethernet settings: %w", wsmanPostErr("401 Unauthorized")), true},
		{"go-wsman 401 bare", wsmanPostErr("401 Unauthorized"), true},
		{"amtpassword sanitized 401", fmt.Errorf("failed to get AMT general settings: %s", "Received 401 unauthorized"), true},
		{"CustomError AMTAuthenticationFailed", fmt.Errorf("step: %w", utils.AMTAuthenticationFailed), true},
		{"go-wsman 400", fmt.Errorf("failed: %w", wsmanPostErr("400 Bad Request")), false},
		{"go-wsman 500", fmt.Errorf("failed: %w", wsmanPostErr("500 Internal Server Error")), false},
		{"other CustomError", utils.WSMANMessageError, false},
		{"plain error", errors.New("connection reset"), false},
		{"nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isAMTUnauthorized(tt.err))
		})
	}
}

// statusTransport answers every request with one fixed HTTP status and body.
type statusTransport struct {
	code int
	body string
}

func (s statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: s.code,
		Status:     fmt.Sprintf("%d %s", s.code, http.StatusText(s.code)),
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestIsAMTUnauthorized_RealWSMANClient drives the real go-wsman client
// through a fake transport, so a go-wsman change to its 401 error text fails
// here. Digest is off: with digest on, a 401 is taken as the challenge.
func TestIsAMTUnauthorized_RealWSMANClient(t *testing.T) {
	tests := []struct {
		name string
		code int
		body string
		want bool
	}{
		{"401", http.StatusUnauthorized, "<html>Unauthorized</html>", true},
		{"500 whose body contains 401", http.StatusInternalServerError, "<html>error 401</html>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := client.NewWsman(client.Parameters{
				Target:    "fake-amt",
				Username:  "admin",
				Password:  "pass",
				UseDigest: false,
				Transport: statusTransport{code: tt.code, body: tt.body},
			})

			_, err := target.Post("<Envelope/>")
			require.Error(t, err)
			require.Equal(t, tt.want, isAMTUnauthorized(fmt.Errorf("step: %w", err)))
		})
	}
}

// TestExecuteMEBxConfiguration_WSMAN401RotatesPassword pins rotation on
// hardware: a migrated step that gets the real go-wsman 401 rotates the
// password with currentPassword and retries with the new one.
func TestExecuteMEBxConfiguration_WSMAN401RotatesPassword(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubSetMEBx(t, fmt.Errorf("failed: %w", wsmanPostErr("401 Unauthorized")))

	po := NewProfileOrchestrator(mebxProfile(), "old-pass", "", false)
	po.currentControlMode = 2
	po.globalPassword = "wrong-pass"

	require.NoError(t, po.executeMEBxConfiguration())

	require.Equal(t, []configure.AMTPasswordOptions{amtPasswordOpts("old-pass", "admin-pass", false)}, *rotations)
	require.Equal(t, []configure.MEBxOptions{mebxOpts("wrong-pass", false), mebxOpts("admin-pass", false)}, *calls)
}

func TestExecuteMEBxConfiguration_WSMAN500DoesNotRotate(t *testing.T) {
	rotations := stubChangeAMTPassword(t)
	calls := stubSetMEBx(t, fmt.Errorf("failed: %w", wsmanPostErr("500 Internal Server Error")))

	po := NewProfileOrchestrator(mebxProfile(), "old-pass", "", false)
	po.currentControlMode = 2
	po.globalPassword = "wrong-pass"

	require.Error(t, po.executeMEBxConfiguration())
	require.Empty(t, *rotations)
	require.Len(t, *calls, 1)
}

// TestExecuteWithPasswordFallback_No401RotationInSettleWindow pins that a 401
// right after this run's activation (the CCM->ACM upgrade leaves mode 1) is the
// transient lockout the settle retries wait out, not a wrong password.
func TestExecuteWithPasswordFallback_No401RotationInSettleWindow(t *testing.T) {
	originalPR := utils.PR
	utils.PR = &failingPasswordReader{}

	defer func() { utils.PR = originalPR }()

	rotations := stubChangeAMTPassword(t)

	po := NewProfileOrchestrator(mebxProfile(), "old-pass", "", false)
	po.currentControlMode = 1
	po.activatedThisRun = true
	po.settleDelaySeconds = 0

	step, calls := recordingStep(wsmanPostErr("401 Unauthorized"), wsmanPostErr("401 Unauthorized"))

	require.NoError(t, po.executeWithPasswordFallback(step))
	require.Empty(t, *rotations)
	require.Equal(t, []string{"admin-pass", "admin-pass", "admin-pass"}, *calls)
}

// TestVerifyAndAlignAMTPassword_Sanitized401RotatesAndReprompts pins the
// hardware shape: the amtpassword step flattens a 401 to plain text, both on
// the probe (rotate) and on a wrong prompted password (prompt again).
func TestVerifyAndAlignAMTPassword_Sanitized401RotatesAndReprompts(t *testing.T) {
	originalPR := utils.PR
	reader := &fixedPasswordReader{password: "old-pass"}
	utils.PR = reader

	t.Cleanup(func() { utils.PR = originalPR })

	sanitized := errors.New("failed to get AMT general settings: Received 401 unauthorized")
	calls := stubChangeAMTPassword(t, sanitized, sanitized)

	po := NewProfileOrchestrator(mebxProfile(), "", "", false)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	require.NoError(t, po.verifyAndAlignAMTPassword())

	require.Equal(t, []configure.AMTPasswordOptions{
		amtPasswordOpts("stale-pass", "admin-pass", false),
		amtPasswordOpts("old-pass", "admin-pass", false),
		amtPasswordOpts("old-pass", "admin-pass", false),
		amtPasswordOpts("admin-pass", "admin-pass", false),
	}, *calls)
	require.Equal(t, 2, reader.reads)
}

// TestExecuteWithPasswordRotation_PromptStopsOnNon401 pins that a non-401
// failure changing the typed password ends the prompt loop with that error.
func TestExecuteWithPasswordRotation_PromptStopsOnNon401(t *testing.T) {
	originalPR := utils.PR
	reader := &fixedPasswordReader{password: "old-pass"}
	utils.PR = reader

	t.Cleanup(func() { utils.PR = originalPR })

	changeErr := errors.New("connection reset")
	rotations := stubChangeAMTPassword(t, changeErr)

	po := NewProfileOrchestrator(mebxProfile(), "", "", false)
	po.currentControlMode = 2
	po.globalPassword = "stale-pass"

	step, calls := recordingStep(wsmanPostErr("401 Unauthorized"))

	err := po.executeWithPasswordRotation(step)
	require.ErrorIs(t, err, changeErr)
	require.Equal(t, 1, reader.reads)
	require.Len(t, *rotations, 1)
	require.Equal(t, []string{"stale-pass"}, *calls)
}
