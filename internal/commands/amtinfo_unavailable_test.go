/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"crypto/tls"
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
)

const certReason = "AMT cert not trusted; use --skip-amt-cert-check"

func certSetupError() error {
	certErr := &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}

	return fmt.Errorf("failed to setup WSMAN client: %w", certErr)
}

func TestWSMANUnavailableReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "no failure", err: nil, want: ""},
		{name: "untrusted AMT certificate", err: certSetupError(), want: certReason},
		{name: "other failure", err: errors.New("failed to get local system account"), want: "WSMAN request failed; run with -v for details"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, wsmanUnavailableReason(tt.err))
		})
	}
}

func TestInfoService_AddConnectionDetails(t *testing.T) {
	t.Run("records local TLS and the first WSMAN failure", func(t *testing.T) {
		service := NewInfoService(nil, WithHECIAvailable(true), WithLocalTLSEnforced(true))
		_ = service.wsmanFailed(certSetupError())
		_ = service.wsmanFailed(errors.New("failed to get MPS SAP"))

		result := &InfoResult{}
		service.addConnectionDetails(result, true)

		if assert.NotNil(t, result.LocalTLSEnforced) {
			assert.True(t, *result.LocalTLSEnforced)
		}

		assert.Equal(t, certReason, result.WSMANUnavailable)
	})

	t.Run("omits local TLS without HECI or for selective flags", func(t *testing.T) {
		for _, tc := range []struct {
			heci, showAll bool
		}{{heci: false, showAll: true}, {heci: true, showAll: false}} {
			service := NewInfoService(nil, WithHECIAvailable(tc.heci), WithLocalTLSEnforced(true))
			result := &InfoResult{}
			service.addConnectionDetails(result, tc.showAll)

			assert.Nil(t, result.LocalTLSEnforced)
			assert.Empty(t, result.WSMANUnavailable)
		}
	})
}

func TestAMTInfoOutput_ShowsConnectionDetailsInline(t *testing.T) {
	enforced := true
	showAll := &AmtInfoCmd{}
	result := &InfoResult{
		LocalTLSEnforced: &enforced,
		RAS:              &amt.RemoteAccessStatus{NetworkStatus: "direct", RemoteStatus: "not connected"},
		WSMANUnavailable: certReason,
	}

	t.Run("device section shows local TLS", func(t *testing.T) {
		out := buildDeviceSection(result, showAll, true, true)

		assert.Contains(t, out, "TLS on Local Ports")
		assert.Contains(t, out, "enforced")
	})

	t.Run("MPS port shows why it is unavailable", func(t *testing.T) {
		out := buildRASSection(result, showAll, true)

		assert.Contains(t, out, "MPS Port")
		assert.Contains(t, out, "Unavailable ("+certReason+")")
	})

	t.Run("MPS port read over WSMAN wins", func(t *testing.T) {
		withPort := *result
		ras := *result.RAS
		ras.MPSPort = 4433
		withPort.RAS = &ras

		out := buildRASSection(&withPort, showAll, true)

		assert.Contains(t, out, "4433")
		assert.NotContains(t, out, "Unavailable")
	})

	t.Run("proxy and user certificate sections show why they are unavailable", func(t *testing.T) {
		all := &AmtInfoCmd{All: true}

		assert.Contains(t, buildProxySection(result, all, true, true), "Unavailable ("+certReason+")")
		assert.Contains(t, buildUserCertsSection(result, all), "Unavailable ("+certReason+")")
	})
}
