/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package commands

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"testing"

	"github.com/device-management-toolkit/rpc-go/v2/pkg/amt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		service := NewInfoService(nil, WithHECIAvailable(true), WithLocalTLSEnforced(true), WithLocalTLSStatusRead(true))
		_ = service.wsmanFailed(certSetupError())
		_ = service.wsmanFailed(errors.New("failed to get MPS SAP"))

		result := &InfoResult{}
		service.addConnectionDetails(result, true)

		if assert.NotNil(t, result.LocalTLSEnforced) {
			assert.True(t, *result.LocalTLSEnforced)
		}

		assert.Equal(t, certReason, result.WSMANUnavailable)
	})

	t.Run("omits local TLS when unread, without HECI, or for selective flags", func(t *testing.T) {
		tests := []struct {
			name                string
			heci, read, showAll bool
		}{
			{name: "status read failed", heci: true, read: false, showAll: true},
			{name: "no HECI", heci: false, read: true, showAll: true},
			{name: "selective flags", heci: true, read: true, showAll: false},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				service := NewInfoService(nil, WithHECIAvailable(tt.heci), WithLocalTLSStatusRead(tt.read))
				result := &InfoResult{}
				service.addConnectionDetails(result, tt.showAll)

				assert.Nil(t, result.LocalTLSEnforced)
				assert.Empty(t, result.WSMANUnavailable)
			})
		}
	})

	t.Run("MPS port is unread only when WSMAN failed", func(t *testing.T) {
		failed := NewInfoService(nil)
		_ = failed.wsmanFailed(certSetupError())
		_, _, err := failed.getMPSInfoFromWSMAN()
		require.Error(t, err)

		result := &InfoResult{}
		failed.addConnectionDetails(result, true)
		assert.True(t, result.mpsUnavailable)

		preProvisioning := NewInfoService(nil)
		_, _, err = preProvisioning.getMPSInfoFromWSMAN()
		require.Error(t, err)

		result = &InfoResult{}
		preProvisioning.addConnectionDetails(result, true)
		assert.False(t, result.mpsUnavailable)
	})
}

func TestAMTInfoOutput_ShowsConnectionDetailsInline(t *testing.T) {
	enforced := true
	showAll := &AmtInfoCmd{}
	result := &InfoResult{
		LocalTLSEnforced: &enforced,
		RAS:              &amt.RemoteAccessStatus{NetworkStatus: "direct", RemoteStatus: "not connected"},
		WSMANUnavailable: certReason,
		mpsUnavailable:   true,
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

	t.Run("MPS port is not blamed for another read's failure", func(t *testing.T) {
		otherFailed := *result
		otherFailed.mpsUnavailable = false

		assert.NotContains(t, buildRASSection(&otherFailed, showAll, true), "MPS Port")
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

	t.Run("an empty certificate read is not reported as unavailable", func(t *testing.T) {
		readEmpty := *result
		readEmpty.UserCerts = map[string]UserCert{}

		out := buildUserCertsSection(&readEmpty, &AmtInfoCmd{UserCert: true})

		assert.Contains(t, out, "No public key certificates found")
		assert.NotContains(t, out, "Unavailable")
	})

	t.Run("table output shows why user certificates are unavailable", func(t *testing.T) {
		var out bytes.Buffer

		require.NoError(t, NewInfoService(nil).OutputTable(&out, result, &AmtInfoCmd{UserCert: true}))

		assert.Contains(t, out.String(), "User Certs")
		assert.Contains(t, out.String(), certReason)
	})
}
