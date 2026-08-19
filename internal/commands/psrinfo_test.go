/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/psr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func testRecord() *psr.PSR {
	return &psr.PSR{
		Status:    0,
		Raw:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		Payload:   []byte{0x05, 0x06},
		UserNonce: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
}

func TestPSRInfoRun(t *testing.T) {
	tests := []struct {
		name       string
		cmd        PSRInfoCmd
		jsonOutput bool
		record     *psr.PSR
		getErr     error
		wantErr    error
	}{
		{
			name:   "successful retrieval",
			record: testRecord(),
		},
		{
			name:       "successful retrieval as JSON",
			jsonOutput: true,
			record:     testRecord(),
		},
		{
			name:    "unconfigured GUID is reported clearly",
			getErr:  psr.ErrPSRGUIDNotConfigured,
			wantErr: psr.ErrPSRGUIDNotConfigured,
		},
		{
			name:    "unsupported platform is reported clearly",
			getErr:  psr.ErrPSRNotSupported,
			wantErr: psr.ErrPSRNotSupported,
		},
		{
			name:    "verification is not yet implemented",
			cmd:     PSRInfoCmd{Verify: true},
			record:  testRecord(),
			wantErr: psr.ErrSignatureVerifyNotImpl,
		},
		{
			name:    "nil record without error is rejected",
			record:  nil,
			wantErr: psr.ErrInvalidResponse,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAMT := mock.NewMockInterface(ctrl)
			mockAMT.EXPECT().GetPSR().Return(tt.record, tt.getErr)

			cmd := tt.cmd
			ctx := &Context{AMTCommand: mockAMT, JsonOutput: tt.jsonOutput}

			err := cmd.Run(ctx)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestPSRInfoWritesBlobToFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	record := testRecord()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetPSR().Return(record, nil)

	// A nested path exercises the directory-creation branch.
	outPath := filepath.Join(t.TempDir(), "nested", "psr.bin")
	cmd := PSRInfoCmd{Output: outPath}

	err := cmd.Run(&Context{AMTCommand: mockAMT})
	require.NoError(t, err)

	written, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, record.Raw, written, "the raw signed blob must be written verbatim")
}

func TestPSRInfoWriteFailureIsSurfaced(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAMT := mock.NewMockInterface(ctrl)
	mockAMT.EXPECT().GetPSR().Return(testRecord(), nil)

	// Point the output at a path under an existing *file* so MkdirAll fails.
	existing := filepath.Join(t.TempDir(), "afile")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0o600))

	cmd := PSRInfoCmd{Output: filepath.Join(existing, "sub", "psr.bin")}

	err := cmd.Run(&Context{AMTCommand: mockAMT})
	assert.Error(t, err)
}

func TestPSRInfoNeverPromptsForAMTPassword(t *testing.T) {
	cmd := &PSRInfoCmd{}
	assert.False(t, cmd.RequiresAMTPassword(),
		"PSR is read over its own MEI client and never authenticates to AMT")
}

func TestPSRInfoRequiresElevation(t *testing.T) {
	// SkipWSMANSetup doubles as "tolerate missing privileges" in
	// AMTBaseCmd.AfterApply. psrinfo has no useful degraded mode, so it must
	// stay unset for an unelevated run to fail with IncorrectPermissions.
	cmd := &PSRInfoCmd{}
	assert.False(t, cmd.SkipWSMANSetup)
}

func TestDescribeRetrievalError(t *testing.T) {
	generic := errors.New("mei exploded")

	assert.ErrorIs(t, describeRetrievalError(psr.ErrPSRGUIDNotConfigured), psr.ErrPSRGUIDNotConfigured)
	assert.ErrorIs(t, describeRetrievalError(psr.ErrPSRNotSupported), psr.ErrPSRNotSupported)
	assert.ErrorIs(t, describeRetrievalError(generic), generic)
	assert.Contains(t, describeRetrievalError(psr.ErrPSRNotSupported).Error(), "CSME 16.1")
}
