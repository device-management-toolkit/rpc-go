/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package deactivate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun_DefaultOptions(t *testing.T) {
	opts := Options{}
	// Run will fail because we're not on a machine with AMT/HECI,
	// but it should fail with a known error, not a panic.
	err := Run(opts)
	assert.Error(t, err, "Run should return an error without AMT hardware")
}

func TestRun_WithPartialUnprovision(t *testing.T) {
	opts := Options{
		AMTPassword:        "test-password",
		PartialUnprovision: true,
	}

	err := Run(opts)
	assert.Error(t, err, "Run should return an error without AMT hardware")
}

func TestRun_WithSkipAMTCertCheck(t *testing.T) {
	opts := Options{
		AMTPassword:      "test-password",
		SkipAMTCertCheck: true,
	}

	err := Run(opts)
	assert.Error(t, err, "Run should return an error without AMT hardware")
}
