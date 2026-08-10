/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package activate

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"syscall"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/apf"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"go.uber.org/mock/gomock"
)

func TestIsConnectionResetErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare EOF", io.EOF, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"url.Error wrapping EOF (the observed CommitChanges symptom)", &url.Error{Op: "Post", URL: "https://localhost:16993/wsman", Err: io.EOF}, true},
		{"APF channel-open failure (port stack restarting on LME retry)", fmt.Errorf("%w, reason code: 2", apf.ErrChannelOpenFailure), true},
		{"url.Error wrapping APF channel-open failure", &url.Error{Op: "Post", URL: "https://localhost:16993/wsman", Err: fmt.Errorf("%w, reason code: 2", apf.ErrChannelOpenFailure)}, true},
		{"unrelated error", errors.New("some other failure"), false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := isConnectionResetErr(tt.err); got != tt.want {
				t.Errorf("isConnectionResetErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestCommitActivation_ConnectionResetButActivated reproduces the AMT20 TLS log:
// CommitChanges returns "Post .../wsman: EOF" because the firmware restarts the
// LMS port stack mid-response, yet the device is actually provisioned. The commit
// must be treated as a success, not a failure.
func TestCommitActivation_ConnectionResetButActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, &url.Error{Op: "Post", URL: "https://localhost:16993/wsman", Err: io.EOF})

	service := &LocalActivationService{
		wsman: mockWSMAN,
		amtCommand: &MockAMTCommand{
			controlMode:       AMTControlModeACM,
			provisioningState: provisioningStatePostProvisioning,
		},
	}

	if err := service.commitActivation(); err != nil {
		t.Fatalf("commitActivation() error = %v, want nil (device is provisioned)", err)
	}
}

// TestCommitActivation_ChannelOpenFailureButActivated reproduces the AMT20 TLS
// log: CommitChanges is cut off by an EOF, the LME transport resets HECI and
// retries, and the retry hits APF_CHANNEL_OPEN_FAILURE (reason code 2) because
// the firmware port stack is still restarting. That channel-open failure — not
// the EOF — is the error that surfaces, yet the device is actually provisioned,
// so the commit must be treated as a success rather than rolled back.
func TestCommitActivation_ChannelOpenFailureButActivated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, &url.Error{
			Op:  "Post",
			URL: "https://localhost:16993/wsman",
			Err: fmt.Errorf("%w, reason code: 2", apf.ErrChannelOpenFailure),
		})

	service := &LocalActivationService{
		wsman: mockWSMAN,
		amtCommand: &MockAMTCommand{
			controlMode:       AMTControlModeACM,
			provisioningState: provisioningStatePostProvisioning,
		},
	}

	if err := service.commitActivation(); err != nil {
		t.Fatalf("commitActivation() error = %v, want nil (device is provisioned)", err)
	}
}

// TestCommitActivation_ConnectionResetStillInProvisioning verifies that a control
// mode alone is not accepted as proof the commit landed. A device that halted
// mid-activation reports ACM while still sitting in provisioning state 1; that is
// a genuine failure and must not be reported as a successful activation.
func TestCommitActivation_ConnectionResetStillInProvisioning(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, io.EOF)

	service := &LocalActivationService{
		wsman: mockWSMAN,
		amtCommand: &MockAMTCommand{
			controlMode:       AMTControlModeACM,
			provisioningState: 1,
		},
	}

	if err := service.commitActivation(); !errors.Is(err, io.EOF) {
		t.Fatalf("commitActivation() error = %v, want io.EOF (still in provisioning)", err)
	}
}

// TestCommitActivation_ProvisioningStateUnreadableFallsBackToControlMode verifies
// the escape hatch: firmware that cannot report a provisioning state must not turn
// genuine activations into failures, so an unreadable state falls back to the
// control-mode decision.
func TestCommitActivation_ProvisioningStateUnreadableFallsBackToControlMode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, io.EOF)

	service := &LocalActivationService{
		wsman: mockWSMAN,
		amtCommand: &MockAMTCommand{
			controlMode:   AMTControlModeACM,
			shouldErrorOn: "GetProvisioningState",
		},
	}

	if err := service.commitActivation(); err != nil {
		t.Fatalf("commitActivation() error = %v, want nil (state unreadable, mode says provisioned)", err)
	}
}

// TestCommitActivation_ConnectionResetStillPreProvisioning verifies that a dropped
// connection with the device still in pre-provisioning is a genuine failure.
func TestCommitActivation_ConnectionResetStillPreProvisioning(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, io.EOF)

	service := &LocalActivationService{
		wsman:      mockWSMAN,
		amtCommand: &MockAMTCommand{controlMode: AMTControlModePreProvisioning},
	}

	if err := service.commitActivation(); !errors.Is(err, io.EOF) {
		t.Fatalf("commitActivation() error = %v, want io.EOF (still pre-provisioning)", err)
	}
}

// TestCommitActivation_NonResetErrorReturnedVerbatim verifies an application-level
// CommitChanges error (e.g. 2057) is returned unchanged without consulting HECI,
// so callers like setupMEBxAndCommit can still branch on it.
func TestCommitActivation_NonResetErrorReturnedVerbatim(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	dataMissing := errors.New("CommitChanges failed: error code 2057")
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, dataMissing)

	// GetControlMode must NOT be consulted for a non-reset error; MockAMTCommand
	// would return a zero control mode, but we assert the original error survives.
	service := &LocalActivationService{
		wsman:      mockWSMAN,
		amtCommand: &MockAMTCommand{controlMode: AMTControlModeACM},
	}

	err := service.commitActivation()
	if !errors.Is(err, dataMissing) {
		t.Fatalf("commitActivation() error = %v, want the original 2057 error", err)
	}
}

// TestCommitActivation_Success covers the ordinary path where CommitChanges
// returns no error.
func TestCommitActivation_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockWSMAN := mock.NewMockWSMANer(ctrl)
	mockWSMAN.EXPECT().
		CommitChanges().
		Return(setupandconfiguration.Response{}, nil)

	service := &LocalActivationService{
		wsman:      mockWSMAN,
		amtCommand: &MockAMTCommand{controlMode: AMTControlModeACM},
	}

	if err := service.commitActivation(); err != nil {
		t.Fatalf("commitActivation() error = %v, want nil", err)
	}
}
