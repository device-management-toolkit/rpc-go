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

// opTimeoutErr wraps a net.Error timeout in a *net.OpError carrying the dial
// target address, mirroring what net.Dialer.DialContext returns on a real
// connect timeout. addr is the "host:port" the dial targeted.
func opTimeoutErr(addr string) error {
	host, port, _ := net.SplitHostPort(addr)

	return &net.OpError{
		Op:   "dial",
		Net:  "tcp4",
		Addr: &net.TCPAddr{IP: net.ParseIP(host), Port: atoiOrZero(port)},
		Err:  timeoutErr{},
	}
}

func atoiOrZero(s string) int {
	n := 0

	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}

		n = n*10 + int(r-'0')
	}

	return n
}

// TestLMSUpButUnready_TimeoutClassification pins the loopback gating: a dial
// timeout only means "LMS up, keep off HECI" when the dial targeted loopback.
// A timeout against a routable address (localhost mis-resolving to a corporate
// IP) must NOT be read as LMS-up, so the caller can fall back to HECI.
func TestLMSUpButUnready_TimeoutClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"loopback timeout is lms-up", opTimeoutErr("127.0.0.1:16992"), true},
		{"routable timeout is not lms-up", opTimeoutErr("10.49.14.88:16992"), false},
		{"bare timeout (no addr) defaults lms-up", context.DeadlineExceeded, true},
		{"eof is lms-up regardless of addr", io.EOF, true},
		{"reset is lms-up", syscall.ECONNRESET, true},
		{"refused is not lms-up", syscall.ECONNREFUSED, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, lmsUpButUnready(tt.err))
		})
	}
}

// TestProbeLMS_RoutableTimeoutFallsBackToHECI reproduces the AMT16 local-mode
// failure: "localhost" resolved to a rotating routable IP, so every dial timed
// out against a host LMS never listens on. probeLMS must return the raw error
// (not errLMSUpButUnready) so the caller falls back to HECI instead of
// hard-failing after the recovery budget.
func TestProbeLMS_RoutableTimeoutFallsBackToHECI(t *testing.T) {
	attempts := 0

	conn, err := probeLMS(func(context.Context) (net.Conn, error) {
		attempts++

		return nil, opTimeoutErr("10.49.14.88:16992")
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.Error(t, err)
	assert.Nil(t, conn)
	assert.NotErrorIs(t, err, errLMSUpButUnready, "a routable-IP timeout must not claim LMS-up; caller needs HECI fallback")
	assert.Equal(t, 1, attempts, "a non-loopback timeout is not a restart; do not burn the recovery budget retrying")
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

// trackedConn records whether it was closed. It embeds net.TCPConn only to
// satisfy net.Conn; none of the embedded methods are called.
type trackedConn struct {
	net.TCPConn

	closed bool
}

func (c *trackedConn) Close() error {
	c.closed = true

	return nil
}

// TestProbeLMS_ClosesConnReturnedWithError covers a dialer that hands back a
// usable-looking conn alongside an error (a connect that completed but whose
// handshake failed). Nothing reads that conn, so probeLMS must close it or the
// retry loop leaks a descriptor per attempt for the whole recovery budget.
func TestProbeLMS_ClosesConnReturnedWithError(t *testing.T) {
	var conns []*trackedConn

	_, err := probeLMS(func(context.Context) (net.Conn, error) {
		c := &trackedConn{}
		conns = append(conns, c)

		return c, io.EOF
	}, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	require.Error(t, err)
	require.NotEmpty(t, conns, "dial should have been attempted")

	for i, c := range conns {
		assert.True(t, c.closed, "conn from attempt %d returned with an error was not closed", i+1)
	}
}

// TestProbeLMS_DoesNotOverrunBudget pins the per-attempt timeout clamp: with a
// dial timeout far larger than the remaining budget, an unclamped attempt would
// block for the full dial timeout past the deadline.
func TestProbeLMS_DoesNotOverrunBudget(t *testing.T) {
	const (
		dialTimeout = 500 * time.Millisecond
		budget      = 50 * time.Millisecond
		retryDelay  = time.Millisecond
	)

	start := time.Now()

	// Block until the context the probe supplies expires, so the attempt lasts
	// exactly as long as probeLMS allows it to.
	_, err := probeLMS(func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()

		return nil, ctx.Err()
	}, dialTimeout, budget, retryDelay)

	elapsed := time.Since(start)

	// Clamped, the single attempt ends with the budget (~50ms). Unclamped it runs
	// the full dial timeout (~500ms). The bound sits well between the two so slow
	// CI machines do not flake it.
	const slack = 200 * time.Millisecond

	require.Error(t, err)
	assert.Less(t, elapsed, budget+slack,
		"probe overran its budget by a full dial timeout; per-attempt timeout is not clamped to the remaining budget")
}
