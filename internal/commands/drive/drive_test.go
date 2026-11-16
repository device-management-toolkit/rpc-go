/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package drive

import (
	"errors"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/internal/commands"
	"github.com/device-management-toolkit/rpc-go/v2/internal/interfaces"
	mock "github.com/device-management-toolkit/rpc-go/v2/internal/mocks"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var (
	errRunFailed   = errors.New("run failed")
	errCloseFailed = errors.New("close failed")
)

// fakeCmd stands in for the activate command. Run opens the client, as EnsureWSMAN does.
type fakeCmd struct {
	client interfaces.WSMANer
	runErr error
	wsman  interfaces.WSMANer
}

func (f *fakeCmd) Validate() error                    { return nil }
func (f *fakeCmd) AfterApply(amt.Interface) error     { return nil }
func (f *fakeCmd) GetWSManClient() interfaces.WSMANer { return f.wsman }

func (f *fakeCmd) Run(*commands.Context) error {
	f.wsman = f.client

	return f.runErr
}

func TestRunClosesWSMANClient(t *testing.T) {
	tests := []struct {
		name     string
		runErr   error
		closeErr error
	}{
		{name: "after a successful run"},
		{name: "after a failed run", runErr: errRunFailed},
		{name: "ignoring a close failure", closeErr: errCloseFailed},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			client := mock.NewMockWSMANer(gomock.NewController(t))
			client.EXPECT().Close().Return(tt.closeErr).Times(1)

			err := Run(&fakeCmd{client: client, runErr: tt.runErr}, &commands.Context{})

			assert.Equal(t, tt.runErr, err)
		})
	}
}

func TestRunWithoutWSMANClient(t *testing.T) {
	assert.NoError(t, Run(&fakeCmd{}, &commands.Context{}))
}
