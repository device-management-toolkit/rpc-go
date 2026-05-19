/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package utils

import (
	"context"
	"net"
	"time"
)

// DetectLMS performs a TCP port-reachability check to determine if Intel LMS is listening.
// When localTLSEnforced is true it probes the TLS port; this only verifies the port is open,
// not that a TLS handshake would succeed.
func DetectLMS(localTLSEnforced bool) bool {
	port := LMSPort
	if localTLSEnforced {
		port = LMSTLSPort
	}

	dialer := &net.Dialer{Timeout: time.Duration(LMSDialerTimeout) * time.Second}

	conn, err := dialer.DialContext(context.Background(), "tcp4", net.JoinHostPort(LMSAddress, port))
	if err != nil {
		return false
	}

	conn.Close()

	return true
}
