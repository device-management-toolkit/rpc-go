/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLMSPortReachable_PortClosed(t *testing.T) {
	// Bind an ephemeral port then release it so the address is guaranteed closed.
	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	assert.NoError(t, err)

	addr := ln.Addr().String()
	ln.Close()

	assert.False(t, lmsPortReachable(addr), "should be false when nothing is listening")
}

func TestLMSPortReachable_PortOpen(t *testing.T) {
	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	assert.NoError(t, err)

	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			conn.Close()
		}
	}()

	assert.True(t, lmsPortReachable(ln.Addr().String()), "should be true when the port is reachable")
}
