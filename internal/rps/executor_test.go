/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/
package rps

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/device-management-toolkit/rpc-go/v2/internal/lm"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/heci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClassifyLMSError pins the relay's error triage. The regression this guards
// against: a read timeout with no bytes (lm.ErrLMSReadTimeoutNoData) is a benign
// quiet round — AMT acknowledging a WSMAN request such as the activating Setup
// without an immediate reply — and must NOT fail the activation on the plain
// (non-TLS-tunnel) RPS relay. Genuine LMS errors must still classify as fatal.
func TestClassifyLMSError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want lmsErrorClass
	}{
		{"heci poll timeout", heci.ErrReadTimeout, lmsErrorPoll},
		{"wrapped heci poll timeout", fmt.Errorf("polling: %w", heci.ErrReadTimeout), lmsErrorPoll},
		{"quiet round no data", lm.ErrLMSReadTimeoutNoData, lmsErrorQuietRound},
		{"wrapped quiet round no data", fmt.Errorf("listen: %w", lm.ErrLMSReadTimeoutNoData), lmsErrorQuietRound},
		{"genuine lms error is fatal", errors.New("connection reset by peer"), lmsErrorFatal},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyLMSError(tt.err))
		})
	}
}

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		val  string
		def  bool
		want bool
	}{
		{"unset returns default true", false, "", true, true},
		{"unset returns default false", false, "", false, false},
		{"true overrides default false", true, "true", false, true},
		{"1 overrides default false", true, "1", false, true},
		{"false overrides default true", true, "false", true, false},
		{"0 overrides default true", true, "0", true, false},
		{"invalid keeps default true", true, "notabool", true, true},
		{"invalid keeps default false", true, "notabool", false, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			const key = "RPC_TEST_ENV_BOOL"
			if tt.set {
				t.Setenv(key, tt.val)
			}

			assert.Equal(t, tt.want, envBool(key, tt.def))
		})
	}
}

// noWait is a wait func that never sleeps and never interrupts, so probe loop
// tests run instantly.
func noWait(time.Duration) error { return nil }

// TestProbeUntilReady_SucceedsFirstAttempt: a port that is immediately ready
// acks after a single probe and never waits.
func TestProbeUntilReady_SucceedsFirstAttempt(t *testing.T) {
	attempts := 0
	waits := 0

	err := probeUntilReady(
		func() error { attempts++; return nil },
		func(time.Duration) error { waits++; return nil },
		15*time.Second, time.Second, "16993",
	)

	require.NoError(t, err)
	assert.Equal(t, 1, attempts, "a ready port needs exactly one probe")
	assert.Equal(t, 0, waits, "no wait when the first probe succeeds")
}

// TestProbeUntilReady_RetriesThenSucceeds: the port becomes ready mid-budget;
// the loop retries and then acks without error.
func TestProbeUntilReady_RetriesThenSucceeds(t *testing.T) {
	attempts := 0

	err := probeUntilReady(
		func() error {
			attempts++
			if attempts < 3 {
				return errors.New("port not ready")
			}

			return nil
		},
		noWait,
		15*time.Second, time.Second, "16993",
	)

	require.NoError(t, err)
	assert.Equal(t, 3, attempts, "should retry until the port accepts a channel")
}

// TestProbeUntilReady_ExhaustsBudgetAndAcks reproduces the pessimal case: the
// port never becomes ready within the budget. The loop must still return nil so
// the caller acks anyway (matching the old blind-sleep behavior), and it must
// not probe past the budget.
func TestProbeUntilReady_ExhaustsBudgetAndAcks(t *testing.T) {
	attempts := 0

	err := probeUntilReady(
		func() error { attempts++; return errors.New("port not ready") },
		noWait,
		5*time.Second, time.Second, "16993",
	)

	require.NoError(t, err, "budget exhaustion must ack anyway, not fail the switch")
	// budget 5s / interval 1s => exactly 5 attempts. Bounded, never infinite.
	assert.Equal(t, 5, attempts, "attempts are derived from budget/interval")
}

// TestProbeUntilReady_ZeroBudgetProbesOnce: a zero (or sub-interval) budget still
// probes exactly once and never waits, so a delay:0 port_switch acks immediately
// after a single readiness check instead of skipping the probe entirely.
func TestProbeUntilReady_ZeroBudgetProbesOnce(t *testing.T) {
	attempts := 0
	waits := 0

	err := probeUntilReady(
		func() error { attempts++; return errors.New("port not ready") },
		func(time.Duration) error { waits++; return nil },
		0, time.Second, "16993",
	)

	require.NoError(t, err)
	assert.Equal(t, 1, attempts, "a zero budget still gets one readiness probe")
	assert.Equal(t, 0, waits, "no wait when only one attempt is allowed")
}

// TestProbeUntilReady_InterruptAborts: an interrupted wait (SIGINT/SIGTERM)
// propagates as an error so the activation loop aborts promptly.
func TestProbeUntilReady_InterruptAborts(t *testing.T) {
	interrupt := errors.New("interrupted by user")

	err := probeUntilReady(
		func() error { return errors.New("port not ready") },
		func(time.Duration) error { return interrupt },
		15*time.Second, time.Second, "16993",
	)

	require.ErrorIs(t, err, interrupt, "a wait interrupt must abort the switch")
}
