/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

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
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, 1, attempts, "success must not retry")
}

func TestProbeLMS_RefusedFailsFast(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return nil, syscall.ECONNREFUSED
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Equal(t, 1, attempts, "a refused dial (LMS down) must not be retried")
}

func TestProbeLMS_TimeoutRetriesThenGivesUp(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return nil, context.DeadlineExceeded
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, errLMSUpButUnready, "an exhausted timeout must signal LMS-up so the caller skips HECI")
	assert.Greater(t, attempts, 1, "a timeout must be retried, not fail on the first attempt")
}

// TestProbeLMS_EOFTreatedAsLMSUp reproduces the AMT21 LMS log: the LMS TLS dial
// is accepted then dropped with EOF while the AMT/LMS port stack restarts. That
// means LMS is up and owns the MEI, so probeLMS must retry and ultimately signal
// errLMSUpButUnready rather than returning a raw error that triggers HECI fallback.
func TestProbeLMS_EOFTreatedAsLMSUp(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return nil, io.EOF
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.ErrorIs(t, err, errLMSUpButUnready, "an EOF dial means LMS is up; caller must not fall back to HECI")
	assert.ErrorIs(t, err, io.EOF, "the underlying dial error should remain wrapped")
	assert.Greater(t, attempts, 1, "an EOF dial must be retried while LMS restarts")
}

// TestProbeLMS_EOFThenSuccess verifies that once LMS finishes restarting, a
// subsequent successful dial is returned and no LMS-up error is surfaced.
func TestProbeLMS_EOFThenSuccess(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++
		if attempts < 2 {
			return nil, io.EOF
		}

		return &net.TCPConn{}, nil
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, 2, attempts, "should stop retrying once LMS answers")
}

func TestProbeLMS_TimeoutThenSuccess(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++
		if attempts < 2 {
			return nil, timeoutErr{}
		}

		return &net.TCPConn{}, nil
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, 2, attempts, "should stop retrying once LMS answers")
}
