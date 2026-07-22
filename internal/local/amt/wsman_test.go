/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// timeoutErr implements net.Error with Timeout() == true.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestIsDialTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"context deadline", context.DeadlineExceeded, true},
		{"net timeout", timeoutErr{}, true},
		{"connection refused", syscall.ECONNREFUSED, false},
		{"generic error", errors.New("boom"), false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDialTimeout(tt.err))
		})
	}
}

func TestProbeLMS_SuccessNoRetry(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return &net.TCPConn{}, nil
	}, time.Millisecond)

	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, 1, attempts, "success must not retry")
}

func TestProbeLMS_RefusedFailsFast(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return nil, syscall.ECONNREFUSED
	}, time.Millisecond)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Equal(t, 1, attempts, "a refused dial (LMS down) must not be retried")
}

func TestProbeLMS_TimeoutRetriesThenGivesUp(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return nil, context.DeadlineExceeded
	}, time.Millisecond)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Equal(t, utils.LMSProbeAttempts, attempts, "a timeout must be retried up to the attempt cap")
}

func TestProbeLMS_TimeoutThenSuccess(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++
		if attempts < 2 {
			return nil, timeoutErr{}
		}

		return &net.TCPConn{}, nil
	}, time.Millisecond)

	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, 2, attempts, "should stop retrying once LMS answers")
}
