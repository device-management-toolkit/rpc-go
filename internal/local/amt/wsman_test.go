/*********************************************************************
 * Copyright (c) Intel Corporation 2024
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package amt

import (
	"context"
	"net"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestIsLMSAvailable_DefaultFalse(t *testing.T) {
	g := NewGoWSMANMessages(utils.LMSAddress)
	assert.False(t, g.IsLMSAvailable(), "should be false before SetupWsmanClient is called")
}

func TestIsLMSAvailable_TrueWhenLMSListening(t *testing.T) {
	// Start a temporary TCP listener simulating LMS on port 16992.
	lc := &net.ListenConfig{}

	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:"+utils.LMSPort)
	if err != nil {
		t.Skipf("cannot bind to port %s (may be in use): %v", utils.LMSPort, err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			conn.Close()
		}
	}()

	g := NewGoWSMANMessages(utils.LMSAddress)

	// SetupWsmanClient with dummy credentials — the TCP probe happens before auth.
	err = g.SetupWsmanClient("admin", "password", false, false, nil)
	assert.NoError(t, err)
	assert.True(t, g.IsLMSAvailable(), "should be true when LMS port is reachable")
}
